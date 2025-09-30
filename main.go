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
	"os"
	"runtime/debug"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	acfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zalando/go-keyring"

	"github.com/alexaandru/confetti"
)

type Creds struct { //nolint:govet // ok//nolint:govet // ok
	Version int `json:"Version"` // Always 1.

	AccessKeyID     string    `json:"AccessKeyId,omitempty"`
	SecretAccessKey string    `json:"SecretAccessKey,omitempty"`
	SessionToken    string    `json:"SessionToken,omitempty"`
	Expiration      time.Time `json:"Expiration,omitzero"`

	RoleArn       string `json:"RoleArn,omitempty"`
	SourceProfile string `json:"SourceProfile,omitempty"`

	SessionTTL time.Duration `json:"SessionTTL,omitzero,format:units"` //nolint:tagliatelle // ok
	SkewPad    time.Duration `json:"SkewPad,omitzero,format:units"`
}

type app struct { //nolint:govet // ok
	config
	iamAPI

	prompt      func(label string, val *string) error
	mkSTSClient func(aws.CredentialsProvider) stsAPI
}

//nolint:inamedparam // ok
type stsAPI interface {
	AssumeRole(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
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
	defaultRegion        = "us-east-1"
	defaultSkewPad       = 120 * time.Second
	defaultSessionTTL    = 3600 * time.Second
	minAllowedSessionTTL = 15 * time.Minute
	maxAllowedSessionTTL = 12 * time.Hour
	defaultProfileName   = "default"
)

//go:embed help.txt
var help string

var version string

func newApp(iamClient iamAPI) (a app, err error) {
	if err = confetti.Load(&a.config, confetti.WithEnv("")); err != nil {
		return
	}

	a.prompt = prompt
	a.SessionTTL = cmp.Or(a.SessionTTL, defaultSessionTTL)
	a.SkewPad = cmp.Or(a.SkewPad, defaultSkewPad)
	a.AWSProfile = cmp.Or(a.AWSProfile, defaultProfileName)
	a.AWSRegion = cmp.Or(a.AWSRegion, defaultRegion)
	a.mkSTSClient = func(creds aws.CredentialsProvider) stsAPI {
		return sts.New(sts.Options{Credentials: creds, Region: a.AWSRegion})
	}

	if iamClient != nil {
		a.iamAPI = iamClient
	} else {
		var cfg aws.Config

		cfg, err = acfg.LoadDefaultConfig(context.Background(), acfg.WithRegion(a.AWSRegion))
		if err != nil {
			return
		}

		a.iamAPI = iam.NewFromConfig(cfg)
	}

	return
}

func krGet(profile string) (string, error) {
	return keyring.Get(keyringService, profile)
}

func krSet(profile, value string) error {
	return keyring.Set(keyringService, profile, value)
}

func krDel(profile string) error {
	return keyring.Delete(keyringService, profile)
}

func (c *Creds) load(name string) (err error) {
	raw, err := krGet(name)
	if err != nil {
		return err
	}

	if raw == "" {
		return fmt.Errorf("profile %q empty JSON", name)
	}

	return json.Unmarshal([]byte(raw), c)
}

func (c *Creds) store(name string) (err error) {
	c.Version = 1

	b, err := json.Marshal(*c)
	if err != nil {
		return err
	}

	return krSet(name, string(b))
}

func (c *Creds) applyDefaults(cfg config) {
	c.SkewPad = cmp.Or(c.SkewPad, cfg.SkewPad)
	c.SessionTTL = min(
		max(cmp.Or(c.SessionTTL, cfg.SessionTTL), minAllowedSessionTTL),
		maxAllowedSessionTTL)
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

	return err
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
		return err
	}

	fmt.Println(string(b))

	return err
}

func (a app) assumeRole(ctx context.Context, base, target Creds) (Creds, error) {
	static := aws.CredentialsProviderFunc(func(ctx context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID:     base.AccessKeyID,
			SecretAccessKey: base.SecretAccessKey,
			SessionToken:    base.SessionToken,
			Source:          keyringService,
		}, nil
	})
	svc := a.mkSTSClient(static)
	input := &sts.AssumeRoleInput{
		RoleArn:         &target.RoleArn,
		RoleSessionName: p(keyringService + "-" + target.SourceProfile),
		DurationSeconds: p(int32(target.SessionTTL.Seconds())),
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

func (a app) resolveAndMaybeRefresh(ctx context.Context, name string) (c Creds, err error) {
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

func (a app) rotateCredentials(ctx context.Context, profileName string) (err error) {
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
	c.AccessKeyID = *newAccessKey.AccessKeyId
	c.SecretAccessKey = *newAccessKey.SecretAccessKey

	if err = c.store(profileName); err != nil {
		return fmt.Errorf("store new credentials: %w", err)
	}

	_, err = a.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{AccessKeyId: &oldAccessKeyID})

	return err
}

func (a app) run(ctx context.Context, args []string) (err error) {
	cmd := "load"
	if len(args) > 1 {
		cmd = args[1]
	}

	switch cmd {
	case "load":
		var c Creds

		c, err = a.resolveAndMaybeRefresh(ctx, a.AWSProfile)
		if err != nil {
			break
		}

		err = c.emitProfile()
	case "rotate":
		err = a.rotateCredentials(ctx, a.AWSProfile)
	case "store", "store-assume":
		var (
			c       Creds
			profile string
		)

		if err = a.prompt("Profile Name (press Enter for '"+a.AWSProfile+"')", &profile); err != nil {
			profile = a.AWSProfile
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
		if err = a.prompt("Deleting profile (press Enter to delete '"+a.AWSProfile+"', "+
			"press anything else to abort)", &a.AWSProfile); err != nil {
			err = krDel(a.AWSProfile)
		}
	case "version":
		fmt.Println(keyringService, version)
	case "help":
		fmt.Println(help)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}

	return
}

func prompt(label string, val *string) (err error) {
	fmt.Print("Enter ", label, ": ")

	if _, err = fmt.Scanln(val); err != nil {
		return fmt.Errorf("read %s: %w", label, err)
	}

	return
}

func p[T any](v T) *T {
	return &v
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
