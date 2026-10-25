// awbus: AWS credential_process helper using Secret Service.
//
// See help.txt for usage.
package main

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	acfg "github.com/aws/aws-sdk-go-v2/config"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"

	"github.com/alexaandru/confetti"
)

type Creds struct { //nolint:govet // ok
	Version int `json:"Version"` // Always 1.

	AccessKeyID     string    `json:"AccessKeyId,omitempty"`
	SecretAccessKey string    `json:"SecretAccessKey,omitempty"`
	SessionToken    string    `json:"SessionToken,omitempty"`
	Expiration      time.Time `json:"Expiration,omitzero"`

	RoleArn       string `json:"RoleArn,omitempty"`
	SourceProfile string `json:"SourceProfile,omitempty"`

	SessionTTL time.Duration `json:"SessionTTL,omitzero"` //nolint:tagliatelle // ok
	SkewPad    time.Duration `json:"SkewPad,omitzero"`
}

type app struct { //nolint:govet // ok
	config
	iamAPI

	prompt          func(label string, val *string) error
	sleep           func(context.Context, time.Duration) error
	mkSTSClient     func(aws.CredentialsProvider) stsAPI
	mkPresignClient func(aws.CredentialsProvider) stsPresignAPI
	mkCognitoClient func() cognitoIdpAPI
}

//nolint:inamedparam // ok
type stsAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	//nolint:lll // ok
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

//nolint:inamedparam,lll // ok
type stsPresignAPI interface {
	PresignGetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

//nolint:inamedparam // ok
type iamAPI interface {
	CreateAccessKey(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}

type config struct {
	AWSRegion,
	AWSProfile string

	SkewPad,
	SessionTTL time.Duration
}

const (
	keyringService       = "awbus"
	stsURLKeyringService = "awbus-sts-url"
	defaultRegion        = "us-east-1"
	defaultSkewPad       = 2 * time.Minute
	defaultSessionTTL    = time.Hour
	minAllowedSessionTTL = 15 * time.Minute
	maxAllowedSessionTTL = 12 * time.Hour
	defaultProfileName   = "default"

	// The SDK's STS presign client never sets X-Amz-Expires, so its URLs run on
	// SigV4's "implicit" validity window rather than an explicit one. AWS's own
	// docs say that window is real but deliberately unpublished and not meant to
	// be depended on:
	//
	//   "IAM manages the implicit validity periods of signatures that don't have
	//   an explicit expiration time. Those implicit periods aren't published.
	//   They don't typically change, but they are managed with security in mind,
	//   so you shouldn't take a dependency on the validity periods."
	//   - https://docs.aws.amazon.com/prescriptive-guidance/latest/presigned-url-best-practices/overview.html
	//
	// So there is no constant to cite for "15 minutes" - not in the SDK, not in
	// AWS docs. What we have instead: live STS rejects a GetCallerIdentity
	// presigned URL at the 15-minute mark with SignatureDoesNotMatch ("Signature
	// expired: <ts> is now earlier than <now> - 15 min."), matching the error
	// format AWS does document (reference_sigv-troubleshooting.html), and others
	// have independently hit the same 15-minute wall:
	// https://github.com/aws/aws-sdk-go/issues/2167
	//
	// Treat this as a conservative estimate to refresh ahead of (via SkewPad),
	// not a guaranteed contract - AWS explicitly reserves the right to change it.
	stsURLAssumedTTL = 15 * time.Minute
)

// IAM access keys are eventually consistent. After rotate we poll STS
// GetCallerIdentity with the new key until it works (or we hit the cap).
// Vars (not consts) so tests can shrink the window without sleeping 30s.
var rotatePropagateInterval = 50 * time.Millisecond //nolint:gochecknoglobals // ok

var rotatePropagateTimeout = 30 * time.Second //nolint:gochecknoglobals // ok

//go:embed help.txt
var help string

var version string

var durationToJS = json.MarshalFunc(func(d time.Duration) ([]byte, error) { //nolint:gochecknoglobals // ok
	return []byte(strconv.Quote(d.String())), nil
})

var durationFromJS = json.UnmarshalFunc(func(data []byte, d *time.Duration) (err error) { //nolint:gochecknoglobals,lll // ok
	s, err := strconv.Unquote(string(data))
	if err != nil {
		return
	}

	*d, err = time.ParseDuration(s)

	return
})

// Package-level keyring helpers (overridable in tests).
var krGet = func(profile string) (string, error) { //nolint:gochecknoglobals // ok
	return keyring.Get(keyringService, profile)
}

var krSet = func(profile, value string) error { //nolint:gochecknoglobals // ok
	return keyring.Set(keyringService, profile, value)
}

var krDel = func(profile string) error { //nolint:gochecknoglobals // ok
	return keyring.Delete(keyringService, profile)
}

func newApp(iamClient iamAPI) (a app, err error) {
	if err = confetti.Load(&a.config, confetti.WithEnv("")); err != nil {
		return
	}

	a.iamAPI = iamClient
	a.prompt = prompt
	a.sleep = sleepCtx
	a.SessionTTL = cmp.Or(a.SessionTTL, defaultSessionTTL)
	a.SkewPad = cmp.Or(a.SkewPad, defaultSkewPad)
	a.AWSProfile = cmp.Or(a.AWSProfile, defaultProfileName)
	a.AWSRegion = cmp.Or(a.AWSRegion, defaultRegion)
	a.mkSTSClient = func(creds aws.CredentialsProvider) stsAPI {
		return sts.New(sts.Options{Credentials: creds, Region: a.AWSRegion})
	}
	a.mkPresignClient = func(creds aws.CredentialsProvider) stsPresignAPI {
		return sts.NewPresignClient(sts.New(sts.Options{Credentials: creds, Region: a.AWSRegion}))
	}
	a.mkCognitoClient = func() cognitoIdpAPI {
		return cip.New(cip.Options{Region: a.AWSRegion})
	}

	return
}

func (a *app) ensureIAMClient(ctx context.Context) (err error) {
	if a.iamAPI != nil {
		return
	}

	cfg, err := acfg.LoadDefaultConfig(ctx, acfg.WithRegion(a.AWSRegion))
	if err != nil {
		return
	}

	a.iamAPI = iam.NewFromConfig(cfg)

	return
}

func (c *Creds) load(name string) (err error) {
	raw, err := krGet(name)
	if err != nil {
		return
	}

	if raw == "" {
		return fmt.Errorf("profile %q empty JSON", name)
	}

	return json.Unmarshal([]byte(raw), c, json.WithUnmarshalers(durationFromJS))
}

func (c *Creds) store(name string) (err error) {
	c.Version = 1

	b, err := json.Marshal(*c, json.WithMarshalers(durationToJS))
	if err != nil {
		return
	}

	return krSet(name, string(b))
}

func (c *Creds) applyDefaults(cfg config) {
	c.SkewPad = cmp.Or(c.SkewPad, cfg.SkewPad)
	c.SessionTTL = min(
		max(cmp.Or(c.SessionTTL, cfg.SessionTTL), minAllowedSessionTTL),
		maxAllowedSessionTTL,
	)
}

func (c *Creds) isStatic() bool {
	return c.RoleArn == ""
}

func (c *Creds) validateStatic() (err error) {
	if c.RoleArn != "" {
		return errors.New("static validation called on non-static profile")
	}

	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return errors.New("static profile missing AccessKeyId or SecretAccessKey")
	}

	if !c.Expiration.IsZero() {
		return errors.New("static profile must not have Expiration")
	}

	return
}

func (c *Creds) credsFresh(now time.Time) bool {
	if c.isStatic() {
		return true
	}

	if c.Expiration.IsZero() {
		return false
	}

	return now.Add(c.SkewPad).Before(c.Expiration)
}

func (c *Creds) emitProfile() (err error) {
	ep := *c

	ep.Version = 1
	ep.RoleArn = ""
	ep.SourceProfile = ""
	ep.SessionTTL = 0
	ep.SkewPad = 0

	b, err := json.Marshal(ep)
	if err != nil {
		return
	}

	fmt.Println(string(b))

	return
}

// credsProvider adapts a resolved Creds into an aws.CredentialsProvider, for
// building an SDK client (STS AssumeRole, STS presign, etc.) out of it.
func credsProvider(c Creds) aws.CredentialsProviderFunc {
	return func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     c.AccessKeyID,
			SecretAccessKey: c.SecretAccessKey,
			SessionToken:    c.SessionToken,
			Source:          keyringService,
		}, nil
	}
}

func (a *app) assumeRole(ctx context.Context, base, target Creds) (Creds, error) {
	svc := a.mkSTSClient(credsProvider(base))
	input := &sts.AssumeRoleInput{
		RoleArn:         &target.RoleArn,
		RoleSessionName: new(keyringService + "-" + target.SourceProfile),
		DurationSeconds: new(int32(target.SessionTTL.Seconds())),
	}

	out, err := svc.AssumeRole(ctx, input)
	if err != nil {
		return target, fmt.Errorf("assume-role %s: %w", target.RoleArn, err)
	}

	if out.Credentials == nil {
		return target, errors.New("assume-role: empty credentials")
	}

	target.AccessKeyID = aws.ToString(out.Credentials.AccessKeyId)
	target.SecretAccessKey = aws.ToString(out.Credentials.SecretAccessKey)
	target.SessionToken = aws.ToString(out.Credentials.SessionToken)

	if out.Credentials.Expiration != nil {
		target.Expiration = *out.Credentials.Expiration
	} else {
		target.Expiration = time.Time{}
	}

	return target, nil
}

func (a *app) resolveAndMaybeRefresh(ctx context.Context, name string) (c Creds, err error) {
	if err = c.load(name); err != nil {
		return
	}

	c.applyDefaults(a.config)

	if c.isStatic() {
		if err = c.validateStatic(); err != nil {
			return Creds{}, fmt.Errorf("profile %q invalid static: %w", name, err)
		}

		return
	}

	if c.SourceProfile == "" {
		return Creds{}, fmt.Errorf("profile %q missing SourceProfile for RoleArn", name)
	}

	base := Creds{}
	if err = base.load(c.SourceProfile); err != nil {
		return Creds{}, fmt.Errorf("load source profile %q: %w", c.SourceProfile, err)
	}

	base.applyDefaults(a.config)

	if !base.isStatic() {
		return Creds{}, fmt.Errorf("source profile %q is not static (multi-hop not allowed)", c.SourceProfile)
	}

	if err = base.validateStatic(); err != nil {
		return Creds{}, fmt.Errorf("source profile %q invalid static: %w", c.SourceProfile, err)
	}

	now := time.Now()
	if c.credsFresh(now) {
		return
	}

	refreshed, err := a.assumeRole(ctx, base, c)
	if err != nil {
		return
	}

	if err = refreshed.store(name); err != nil {
		return Creds{}, fmt.Errorf("persist refreshed profile %q: %w", name, err)
	}

	return refreshed, nil
}

func (a *app) rotateCredentials(ctx context.Context, profileName string) (err error) {
	if err = a.ensureIAMClient(ctx); err != nil {
		return fmt.Errorf("initialize IAM client: %w", err)
	}

	var c Creds

	if err = c.load(profileName); err != nil {
		return fmt.Errorf("load profile %q: %w", profileName, err)
	}

	if !c.isStatic() {
		return fmt.Errorf("profile %q is not a static profile (rotation only supported for static credentials)", profileName)
	}

	if err = c.validateStatic(); err != nil {
		return fmt.Errorf("profile %q has invalid static credentials: %w", profileName, err)
	}

	resp, err := a.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{})
	if err != nil {
		return fmt.Errorf("create new access key: %w", err)
	}

	if resp.AccessKey == nil {
		return errors.New("create access key returned nil access key")
	}

	newAccessKey := resp.AccessKey
	oldAccessKeyID := c.AccessKeyID
	// Clone out of the SDK response: aws.ToString shares the backing array, and
	// later IAM calls can reuse that buffer — leaving c.SecretAccessKey corrupted
	// while the keyring copy from store() stays correct (exactly the "poll fails
	// for N seconds, then aws works instantly" failure mode).
	c.AccessKeyID = strings.Clone(aws.ToString(newAccessKey.AccessKeyId))
	c.SecretAccessKey = strings.Clone(aws.ToString(newAccessKey.SecretAccessKey))
	c.SessionToken = ""

	newKeyID := c.AccessKeyID

	if err = c.store(profileName); err != nil {
		// IAM allows only 2 keys per user; roll back the new key so a failed
		// store cannot leave an orphan that blocks the next rotate.
		if _, delErr := a.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
			AccessKeyId: &newKeyID,
		}); delErr != nil {
			return fmt.Errorf("store new credentials: %w",
				errors.Join(err, fmt.Errorf("delete orphaned key %s: %w", newKeyID, delErr)))
		}

		return fmt.Errorf("store new credentials: %w", err)
	}

	if _, err = a.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{AccessKeyId: &oldAccessKeyID}); err != nil {
		return fmt.Errorf(
			"delete old access key %s (new key is stored; delete the old key in IAM to stay under the 2-key limit): %w",
			oldAccessKeyID, err,
		)
	}

	// Poll with what credential_process will actually serve, not the in-memory view.
	var stored Creds
	if err = stored.load(profileName); err != nil {
		return fmt.Errorf("reload rotated profile %q: %w", profileName, err)
	}

	return a.waitForCredsPropagation(ctx, stored)
}

// waitForCredsPropagation polls STS GetCallerIdentity with c until IAM accepts
// the key, or rotatePropagateTimeout elapses (warns on stderr; does not fail
// the rotate — the keyring already holds the new credentials).
func (a *app) waitForCredsPropagation(ctx context.Context, c Creds) (err error) {
	sleep := a.sleep
	if sleep == nil {
		sleep = sleepCtx
	}

	mk := a.mkSTSClient
	if mk == nil {
		mk = func(creds aws.CredentialsProvider) stsAPI {
			return sts.New(sts.Options{Credentials: creds, Region: a.AWSRegion})
		}
	}

	svc := mk(credsProvider(c))
	deadline := time.Now().Add(rotatePropagateTimeout)

	fmt.Fprintln(os.Stderr, "awbus: rotated; waiting for IAM to accept the new access key...")

	var lastErr error

	for {
		if _, lastErr = svc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); lastErr == nil {
			return
		}

		if err = ctx.Err(); err != nil {
			return fmt.Errorf("wait for IAM propagation: %w", err)
		}

		if !time.Now().Before(deadline) {
			fmt.Fprintf(os.Stderr, "awbus: warning: new access key not usable after %s: %v\n",
				rotatePropagateTimeout, lastErr)

			return
		}

		if err = sleep(ctx, rotatePropagateInterval); err != nil {
			return fmt.Errorf("wait for IAM propagation: %w", err)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) (err error) {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

//nolint:gocognit,cyclop,funlen,nakedret,gocyclo // ok
func (a *app) run(ctx context.Context, args []string) (err error) {
	// Parse flags and extract remaining args.
	var profileOverride, tokenKind, userFlag, poolFlag string

	filteredArgs := []string{args[0]} // Keep program name.

	for i := 1; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-profile" && i+1 < len(args):
			profileOverride = args[i+1]
			i++ // Skip the next arg (profile value).
		case len(arg) > 9 && arg[:9] == "-profile=":
			profileOverride = arg[9:]
		case arg == "-token" && i+1 < len(args):
			tokenKind = args[i+1]
			i++
		case len(arg) > 7 && arg[:7] == "-token=":
			tokenKind = arg[7:]
		case arg == "-user" && i+1 < len(args):
			userFlag = args[i+1]
			i++
		case len(arg) > 6 && arg[:6] == "-user=":
			userFlag = arg[6:]
		case arg == "-pool" && i+1 < len(args):
			poolFlag = args[i+1]
			i++
		case len(arg) > 6 && arg[:6] == "-pool=":
			poolFlag = arg[6:]
		default:
			filteredArgs = append(filteredArgs, arg)
		}
	}

	// Override profile if specified.
	if profileOverride != "" {
		a.AWSProfile = profileOverride
	}

	poolName := cmp.Or(poolFlag, defaultPoolName)

	cmd := "load"
	if len(filteredArgs) > 1 {
		cmd = filteredArgs[1]
	}

	switch cmd {
	case "load":
		var c Creds

		c, err = a.resolveAndMaybeRefresh(ctx, a.AWSProfile)
		if err != nil {
			break
		}

		err = c.emitProfile()
	case "sts-url":
		var url string

		url, err = a.resolveSTSURL(ctx)
		if err != nil {
			break
		}

		fmt.Println(url)
	case "jwt":
		var token string

		token, err = a.jwt(ctx, poolName, userFlag, tokenKind)
		if err != nil {
			break
		}

		fmt.Println(token)
	case "jwt-add-user":
		err = a.addCognitoUser(poolName)
	case "jwt-set-default-user":
		err = a.setDefaultCognitoUser(poolName, userFlag)
	case "rotate":
		err = a.rotateCredentials(ctx, a.AWSProfile)
	case "store", "store-assume":
		var (
			c       Creds
			profile string
			ok      bool
		)

		if err = a.prompt("Profile Name (press Enter for '"+a.AWSProfile+"')", &profile); err != nil {
			profile = a.AWSProfile
		}

		if ok, err = a.confirmProfileOverwrite(profile); err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("aborted: profile %q already exists", profile)
			}

			break
		}

		if cmd == "store-assume" { //nolint:nestif // ok
			if err = a.prompt("RoleArn", &c.RoleArn); err != nil {
				break
			}

			if err = a.prompt("SourceProfile", &c.SourceProfile); err != nil {
				break
			}
		} else {
			if err = a.prompt("AccessKeyId", &c.AccessKeyID); err != nil {
				break
			}

			if err = a.prompt("SecretAccessKey", &c.SecretAccessKey); err != nil {
				break
			}
		}

		err = c.store(profile)
	case "delete":
		if !a.confirmProfileDelete(a.AWSProfile) {
			err = fmt.Errorf("aborted: profile %q not deleted", a.AWSProfile)
			break
		}

		err = krDel(a.AWSProfile)
	case "version":
		fmt.Println(keyringService, version)
	case "get":
		if len(filteredArgs) < 4 { //nolint:mnd // ok
			err = errors.New("get command requires service and username arguments")
			break
		}

		var out string

		out, err = keyring.Get(filteredArgs[2], filteredArgs[3])
		if err != nil {
			break
		}

		fmt.Println(out)
	case "put":
		var service, username, secret string

		if len(filteredArgs) >= 3 { //nolint:mnd // ok
			service = filteredArgs[2]
		}

		if len(filteredArgs) >= 4 { //nolint:mnd // ok
			username = filteredArgs[3]
		}

		var (
			stat  os.FileInfo
			input []byte
		)

		if stat, err = os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
			if input, err = io.ReadAll(os.Stdin); err != nil {
				err = fmt.Errorf("read secret from stdin: %w", err)
				break
			}

			secret = strings.TrimRight(string(input), "\r\n")
		}

		if err = a.promptIfEmpty("Service", &service); err != nil {
			break
		}

		if err = a.promptIfEmpty("Username", &username); err != nil {
			break
		}

		if err = a.promptIfEmpty("Secret", &secret); err != nil {
			break
		}

		err = keyring.Set(service, username, secret)
	case "help":
		fmt.Println(help)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}

	return
}

func isSecretLabel(label string) bool {
	l := strings.ToLower(label)

	return strings.Contains(l, "secret") || strings.Contains(l, "password")
}

func prompt(label string, val *string) (err error) {
	fmt.Print("Enter ", label, ": ")

	fd := int(os.Stdin.Fd())
	if isSecretLabel(label) && term.IsTerminal(fd) {
		var b []byte

		b, err = term.ReadPassword(fd)

		fmt.Println()

		if err != nil {
			return fmt.Errorf("read %s: %w", label, err)
		}

		*val = string(b)

		return
	}

	if _, err = fmt.Scanln(val); err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}

	return
}

func (a *app) promptIfEmpty(label string, val *string) (err error) {
	if *val == "" {
		return a.prompt(label, val)
	}

	return
}

// confirmProfileOverwrite returns ok=true when profile is absent or the user
// answers y/yes. Empty / anything else aborts (ok=false, err=nil).
func (a *app) confirmProfileOverwrite(profile string) (ok bool, err error) {
	if _, err = krGet(profile); errors.Is(err, keyring.ErrNotFound) {
		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("check existing profile %q: %w", profile, err)
	}

	var answer string

	if promptErr := a.prompt(fmt.Sprintf("Profile %q exists; overwrite? [y/N]", profile), &answer); promptErr != nil {
		// Empty Enter from Scanln surfaces as an error — treat as "no".
		return false, nil //nolint:nilerr // ok
	}

	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes", nil
}

// confirmProfileDelete reports whether the user confirmed with Enter or y/yes.
// The answer is never written into a.AWSProfile.
func (a *app) confirmProfileDelete(profile string) bool {
	var answer string

	if err := a.prompt(
		fmt.Sprintf("Delete profile %q? [Enter/y to confirm]", profile),
		&answer,
	); err != nil {
		// Empty Enter from Scanln surfaces as an error — treat as confirm.
		return true
	}

	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes"
}

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, msg+": %v\n", err)
		os.Exit(1)
	}
}

func main() {
	a, err := newApp(nil)
	die("config error", err)

	err = a.run(context.Background(), os.Args)
	die("error", err)
}

//nolint:gochecknoinits // ok
func init() {
	info, ok := debug.ReadBuildInfo()
	if ok {
		version = info.Main.Version
	}
}
