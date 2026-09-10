package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"time"

	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/zalando/go-keyring"
)

// CognitoUser is one username/password pair authenticating against a
// CognitoPool.
type CognitoUser struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
}

// CognitoPool is a Cognito User Pool app client, identified by a pool name
// (the -pool flag) entirely independent of any AWS profile - Cognito
// InitiateAuth needs no AWS credentials, so its config is never stored
// alongside AWS creds. Holds the set of users that may authenticate against
// it and which one is the default (used when -user is omitted).
type CognitoPool struct {
	UserPoolID  string        `json:"UserPoolId"`
	ClientID    string        `json:"ClientId"`
	DefaultUser string        `json:"DefaultUser,omitempty"`
	Users       []CognitoUser `json:"Users"`
}

// jwtCache is a cached Cognito authentication result, keyed by
// pool+user in its own keyring service so it never collides with
// CognitoPool's own config storage.
type jwtCache struct {
	IssuedAt     time.Time     `json:"IssuedAt"`
	IDToken      string        `json:"IdToken"`
	AccessToken  string        `json:"AccessToken"`
	RefreshToken string        `json:"RefreshToken"`
	ExpiresIn    time.Duration `json:"ExpiresIn"`
}

//nolint:inamedparam // ok
type cognitoIdpAPI interface {
	InitiateAuth(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error)
}

const (
	cognitoKeyringService = "awbus-cognito"
	jwtKeyringService     = "awbus-jwt"
	defaultPoolName       = "default"
)

// jwt resolves the JWT for pool poolName and userFlag, returning the
// IdToken or AccessToken per tokenKind ("id" or "access").
func (a *app) jwt(ctx context.Context, poolName, userFlag, tokenKind string) (string, error) {
	cache, err := a.resolveJWT(ctx, poolName, userFlag)
	if err != nil {
		return "", err
	}

	switch tokenKind {
	case "", "id":
		return cache.IDToken, nil
	case "access":
		return cache.AccessToken, nil
	default:
		return "", fmt.Errorf("unknown -token kind %q (want \"id\" or \"access\")", tokenKind)
	}
}

func jwtCacheKey(poolName string, pool CognitoPool, username string) string {
	return poolName + "/" + pool.UserPoolID + "/" + pool.ClientID + "/" + username
}

func (p *CognitoPool) load(poolName string) (err error) {
	raw, err := keyring.Get(cognitoKeyringService, poolName)
	if err != nil {
		return
	}

	return json.Unmarshal([]byte(raw), p)
}

func (p *CognitoPool) store(poolName string) (err error) {
	b, err := json.Marshal(*p)
	if err != nil {
		return
	}

	return keyring.Set(cognitoKeyringService, poolName, string(b))
}

func (c *jwtCache) load(key string) (err error) {
	raw, err := keyring.Get(jwtKeyringService, key)
	if err != nil {
		return
	}

	return json.Unmarshal([]byte(raw), c, json.WithUnmarshalers(durationFromJS))
}

func (c *jwtCache) store(key string) (err error) {
	b, err := json.Marshal(*c, json.WithMarshalers(durationToJS))
	if err != nil {
		return
	}

	return keyring.Set(jwtKeyringService, key, string(b))
}

func (c *jwtCache) fresh(now time.Time, skewPad time.Duration) bool {
	return c.IDToken != "" && now.Add(skewPad).Before(c.IssuedAt.Add(c.ExpiresIn))
}

// resolveCognitoUser resolves userFlag against pool's stored users, per the
// -user flag rules: "" means the pool's default user, falling back to "-"
// if the pool has none yet; "-" means prompt for a username; an
// unambiguous prefix of a stored username selects that user; and a name
// matching no stored user is registered with awbus as a new local entry
// (prompting for its password - the Cognito user itself must already
// exist, awbus never creates or modifies users in Cognito), becoming the
// pool's default if it's the first user.
//
// On any mutation of pool.Users/pool.DefaultUser, changed is true and the
// caller is responsible for persisting pool.
func resolveCognitoUser(pool *CognitoPool, userFlag string, promptFn func(string, *string) error) (user CognitoUser, changed bool, err error) { //nolint:lll // ok
	if userFlag == "" {
		userFlag = pool.DefaultUser
	}

	if userFlag == "-" || userFlag == "" {
		var typed string

		if err = promptFn("Username", &typed); err != nil {
			err = fmt.Errorf("prompt username: %w", err)
			return
		}

		return resolveCognitoUser(pool, typed, promptFn)
	}

	user, found, err := matchCognitoUser(pool, userFlag)
	if err != nil || found {
		return
	}

	return newCognitoUser(pool, userFlag, promptFn)
}

// matchCognitoUser looks up userFlag against pool's stored users: an exact
// match or an unambiguous prefix match returns found=true; no match returns
// found=false with a nil error; an ambiguous prefix returns a non-nil err.
func matchCognitoUser(pool *CognitoPool, userFlag string) (user CognitoUser, found bool, err error) {
	var matches []CognitoUser

	for _, u := range pool.Users {
		if u.Username == userFlag {
			user, found = u, true
			return
		}

		if strings.HasPrefix(u.Username, userFlag) {
			matches = append(matches, u)
		}
	}

	switch len(matches) {
	case 0:
	case 1:
		user, found = matches[0], true
	default:
		names := make([]string, len(matches))
		for i, m := range matches {
			names[i] = m.Username
		}

		err = fmt.Errorf("ambiguous user prefix %q matches: %s", userFlag, strings.Join(names, ", "))
	}

	return
}

// findCognitoUser resolves userFlag to an existing pool user, prompting for
// a username if userFlag is "" or "-" (same prompt as resolveCognitoUser),
// but - unlike resolveCognitoUser - erroring instead of registering a new
// one if nothing matches.
func findCognitoUser(pool *CognitoPool, userFlag string, promptFn func(string, *string) error) (user CognitoUser, err error) { //nolint:lll // ok
	if userFlag == "" || userFlag == "-" {
		var typed string

		if err = promptFn("Username", &typed); err != nil {
			err = fmt.Errorf("prompt username: %w", err)
			return
		}

		return findCognitoUser(pool, typed, promptFn)
	}

	user, found, err := matchCognitoUser(pool, userFlag)
	if err != nil {
		return
	}

	if !found {
		err = fmt.Errorf("no user matching %q", userFlag)
	}

	return
}

func newCognitoUser(pool *CognitoPool, username string, promptFn func(string, *string) error) (user CognitoUser, changed bool, err error) { //nolint:lll // ok
	var password string

	if err = promptFn("Password for "+username, &password); err != nil {
		err = fmt.Errorf("prompt password: %w", err)
		return
	}

	user = CognitoUser{Username: username, Password: password}
	pool.Users = append(pool.Users, user)

	if pool.DefaultUser == "" {
		pool.DefaultUser = username
	}

	changed = true

	return
}

// resolveJWT resolves (auto-provisioning if needed) the Cognito pool named
// poolName, resolves userFlag against it, and returns a fresh jwtCache for
// that pool+user - from cache, refresh token, or a full username/password
// re-auth, in that order of preference.
func (a *app) resolveJWT(ctx context.Context, poolName, userFlag string) (cache jwtCache, err error) {
	var pool CognitoPool

	if err = pool.load(poolName); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		err = fmt.Errorf("load Cognito pool %q: %w", poolName, err)
		return
	}

	changed := false

	if pool.UserPoolID == "" {
		if err = a.prompt("UserPoolId", &pool.UserPoolID); err != nil {
			err = fmt.Errorf("prompt UserPoolId: %w", err)
			return
		}

		changed = true
	}

	if pool.ClientID == "" {
		if err = a.prompt("ClientId", &pool.ClientID); err != nil {
			err = fmt.Errorf("prompt ClientId: %w", err)
			return
		}

		changed = true
	}

	user, userChanged, err := resolveCognitoUser(&pool, userFlag, a.prompt)
	if err != nil {
		return
	}

	if changed || userChanged {
		if err = pool.store(poolName); err != nil {
			err = fmt.Errorf("persist Cognito pool %q: %w", poolName, err)
			return
		}
	}

	return a.resolveJWTForUser(ctx, jwtCacheKey(poolName, pool, user.Username), pool, user)
}

func (a *app) resolveJWTForUser(ctx context.Context, key string, pool CognitoPool, user CognitoUser) (cache jwtCache, err error) { //nolint:lll // ok
	now := time.Now()
	if err = cache.load(key); err == nil && cache.fresh(now, a.SkewPad) {
		return
	}

	svc := a.mkCognitoClient()

	//nolint:nestif // ok
	if cache.RefreshToken != "" {
		if cache, err = a.initiateAuth(ctx, svc, pool, types.AuthFlowTypeRefreshTokenAuth, map[string]string{
			"REFRESH_TOKEN": cache.RefreshToken,
		}, now); err == nil {
			cache.RefreshToken = ""

			var stale jwtCache

			if e := stale.load(key); e == nil {
				cache.RefreshToken = stale.RefreshToken
			}

			if err = cache.store(key); err != nil {
				err = fmt.Errorf("persist refreshed JWT cache: %w", err)
			}

			return
		}
	}

	cache, err = a.initiateAuth(ctx, svc, pool, types.AuthFlowTypeUserPasswordAuth, map[string]string{
		"USERNAME": user.Username,
		"PASSWORD": user.Password,
	}, now)
	if err != nil {
		return
	}

	if err = cache.store(key); err != nil {
		err = fmt.Errorf("persist JWT cache: %w", err)
	}

	return
}

func (a *app) initiateAuth(ctx context.Context, svc cognitoIdpAPI, pool CognitoPool, flow types.AuthFlowType, params map[string]string, now time.Time) (cache jwtCache, err error) { //nolint:lll // ok
	out, err := svc.InitiateAuth(ctx, &cip.InitiateAuthInput{
		AuthFlow:       flow,
		ClientId:       &pool.ClientID,
		AuthParameters: params,
	})
	if err != nil {
		err = fmt.Errorf("cognito InitiateAuth (%s): %w", flow, err)
		return
	}

	if out.ChallengeName != "" {
		err = fmt.Errorf("cognito InitiateAuth (%s): unhandled challenge %s", flow, out.ChallengeName)
		return
	}

	if out.AuthenticationResult == nil {
		err = fmt.Errorf("cognito InitiateAuth (%s): empty authentication result", flow)
		return
	}

	res := out.AuthenticationResult

	return jwtCache{
		IDToken:      strOrEmpty(res.IdToken),
		AccessToken:  strOrEmpty(res.AccessToken),
		RefreshToken: strOrEmpty(res.RefreshToken),
		IssuedAt:     now,
		ExpiresIn:    time.Duration(res.ExpiresIn) * time.Second,
	}, nil
}

// loadConfiguredCognitoPool loads the pool named poolName, erroring if it
// hasn't been configured yet (run `jwt` first).
func loadConfiguredCognitoPool(poolName string) (pool CognitoPool, err error) {
	if err = pool.load(poolName); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			err = fmt.Errorf("no Cognito pool named %q configured - run `jwt -pool %s` first", poolName, poolName)
		} else {
			err = fmt.Errorf("load Cognito pool %q: %w", poolName, err)
		}

		return
	}

	if pool.UserPoolID == "" {
		err = fmt.Errorf("no Cognito pool named %q configured - run `jwt -pool %s` first", poolName, poolName)
	}

	return
}

// addCognitoUser registers an additional, already-existing Cognito user
// with the pool named poolName, prompting for its username and password. It
// errors if the username is already registered, and does not call Cognito
// at all - it only stores credentials for later use by jwt.
func (a *app) addCognitoUser(poolName string) (err error) {
	pool, err := loadConfiguredCognitoPool(poolName)
	if err != nil {
		return
	}

	var username string

	if err = a.prompt("Username", &username); err != nil {
		err = fmt.Errorf("prompt username: %w", err)
		return
	}

	for _, u := range pool.Users {
		if u.Username == username {
			err = fmt.Errorf("user %q already exists", username)
			return
		}
	}

	var password string

	if err = a.prompt("Password for "+username, &password); err != nil {
		err = fmt.Errorf("prompt password: %w", err)
		return
	}

	pool.Users = append(pool.Users, CognitoUser{Username: username, Password: password})

	if pool.DefaultUser == "" {
		pool.DefaultUser = username
	}

	return pool.store(poolName)
}

// setDefaultCognitoUser sets the pool named poolName's default user to the
// one userFlag resolves to (same prefix-matching rules as -user
// elsewhere), erroring instead of registering a new one if nothing matches.
func (a *app) setDefaultCognitoUser(poolName, userFlag string) (err error) {
	pool, err := loadConfiguredCognitoPool(poolName)
	if err != nil {
		return
	}

	user, err := findCognitoUser(&pool, userFlag, a.prompt)
	if err != nil {
		return
	}

	pool.DefaultUser = user.Username

	return pool.store(poolName)
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}

	return *s
}
