package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"testing"
	"time"

	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/zalando/go-keyring"
)

type mockCognitoClient struct {
	initiateAuthFunc func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error)
}

func (m *mockCognitoClient) InitiateAuth(ctx context.Context, input *cip.InitiateAuthInput, opts ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
	return m.initiateAuthFunc(ctx, input, opts...)
}

func TestResolveCognitoUser(t *testing.T) { //nolint:funlen,gocognit // ok
	tests := []struct {
		promptFn     func(t *testing.T) func(string, *string) error
		name         string
		userFlag     string
		wantUsername string
		wantErr      string
		startDefault string
		wantDefault  string
		startUsers   []CognitoUser
		wantChanged  bool
	}{
		{
			name:         "empty flag uses default user",
			userFlag:     "",
			startUsers:   []CognitoUser{{Username: "alice", Password: "p1"}, {Username: "alex", Password: "p2"}},
			startDefault: "alice",
			wantUsername: "alice",
			wantDefault:  "alice",
		},
		{
			name:         "unambiguous prefix matches",
			userFlag:     "alex",
			startUsers:   []CognitoUser{{Username: "alice", Password: "p1"}, {Username: "alex", Password: "p2"}},
			startDefault: "alice",
			wantUsername: "alex",
			wantDefault:  "alice",
		},
		{
			name:         "ambiguous prefix errors",
			userFlag:     "al",
			startUsers:   []CognitoUser{{Username: "alice", Password: "p1"}, {Username: "alex", Password: "p2"}},
			startDefault: "alice",
			wantErr:      `ambiguous user prefix "al" matches: alice, alex`,
		},
		{
			name:     "unknown name creates a new user and becomes default when pool has none",
			userFlag: "alice",
			promptFn: func(t *testing.T) func(string, *string) error {
				t.Helper()

				return func(label string, val *string) error {
					if label != "Password for alice" {
						t.Fatalf("unexpected prompt label %q", label)
					}

					*val = "newpass"

					return nil
				}
			},
			wantUsername: "alice",
			wantChanged:  true,
			wantDefault:  "alice",
		},
		{
			name:         "unknown name creates a new user without stealing existing default",
			userFlag:     "carol",
			startUsers:   []CognitoUser{{Username: "alice", Password: "p1"}},
			startDefault: "alice",
			promptFn: func(t *testing.T) func(string, *string) error {
				t.Helper()

				return func(_ string, val *string) error {
					*val = "carolpass"
					return nil
				}
			},
			wantUsername: "carol",
			wantChanged:  true,
			wantDefault:  "alice",
		},
		{
			name:     "dash prompts for a username then resolves it",
			userFlag: "-",
			promptFn: func(t *testing.T) func(string, *string) error {
				t.Helper()

				calls := 0

				return func(label string, val *string) error {
					calls++
					switch calls {
					case 1:
						if label != "Username" {
							t.Fatalf("unexpected prompt label %q", label)
						}

						*val = "dave"
					case 2:
						*val = "davepass"
					}

					return nil
				}
			},
			wantUsername: "dave",
			wantChanged:  true,
			wantDefault:  "dave",
		},
		{
			name:     "prompt error propagates",
			userFlag: "-",
			promptFn: func(t *testing.T) func(string, *string) error {
				t.Helper()

				return func(string, *string) error {
					return errors.New("user aborted")
				}
			},
			wantErr: "prompt username: user aborted",
		},
		{
			name:         "non-exact prefix matching exactly one user",
			userFlag:     "al",
			startUsers:   []CognitoUser{{Username: "alice", Password: "p1"}, {Username: "bob", Password: "p2"}},
			startDefault: "alice",
			wantUsername: "alice",
			wantDefault:  "alice",
		},
		{
			name:     "new user password prompt error propagates",
			userFlag: "carol",
			promptFn: func(t *testing.T) func(string, *string) error {
				t.Helper()

				return func(label string, val *string) error {
					if label != "Password for carol" {
						t.Fatalf("unexpected prompt label %q", label)
					}

					return errors.New("user aborted")
				}
			},
			wantErr: "prompt password: user aborted",
		},
		{
			name:     "empty flag with no default prompts for username instead of creating a blank user",
			userFlag: "",
			promptFn: func(t *testing.T) func(string, *string) error {
				t.Helper()

				calls := 0

				return func(label string, val *string) error {
					calls++
					switch calls {
					case 1:
						if label != "Username" {
							t.Fatalf("unexpected prompt label %q", label)
						}

						*val = "erin"
					case 2:
						if label != "Password for erin" {
							t.Fatalf("unexpected prompt label %q", label)
						}

						*val = "erinpass"
					}

					return nil
				}
			},
			wantUsername: "erin",
			wantChanged:  true,
			wantDefault:  "erin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := &CognitoPool{DefaultUser: tt.startDefault, Users: slices.Clone(tt.startUsers)}

			promptFn := func(string, *string) error { return errors.New("prompt not expected") }
			if tt.promptFn != nil {
				promptFn = tt.promptFn(t)
			}

			user, changed, err := resolveCognitoUser(pool, tt.userFlag, promptFn)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if user.Username != tt.wantUsername {
				t.Errorf("username = %q, want %q", user.Username, tt.wantUsername)
			}

			if changed != tt.wantChanged {
				t.Errorf("changed = %v, want %v", changed, tt.wantChanged)
			}

			if pool.DefaultUser != tt.wantDefault {
				t.Errorf("pool.DefaultUser = %q, want %q", pool.DefaultUser, tt.wantDefault)
			}
		})
	}
}

func TestAppJWT(t *testing.T) { //nolint:funlen,gocognit,cyclop // ok
	basePool := CognitoPool{
		UserPoolID:  "pool1",
		ClientID:    "client1",
		DefaultUser: "alice",
		Users:       []CognitoUser{{Username: "alice", Password: "secret"}},
	}

	tests := []struct {
		cognito   func(t *testing.T) *mockCognitoClient
		setupFn   func(t *testing.T)
		prompt    func(string, *string) error
		name      string
		userFlag  string
		tokenKind string
		wantToken string
		wantErr   bool
	}{
		{
			name: "fresh cache is reused without calling cognito",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)

				cache := jwtCache{IDToken: "cached-id", AccessToken: "cached-access", IssuedAt: time.Now(), ExpiresIn: time.Hour}
				b, _ := json.Marshal(cache, json.WithMarshalers(durationToJS))     //nolint:errcheck // ok
				keyring.Set(jwtKeyringService, "p/pool1/client1/alice", string(b)) //nolint:errcheck,gosec // ok
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					t.Fatal("InitiateAuth should not be called for a fresh cache")
					return nil, nil
				}}
			},
			wantToken: "cached-id",
		},
		{
			name: "no cache does full password auth",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(_ context.Context, in *cip.InitiateAuthInput, _ ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					if in.AuthFlow != types.AuthFlowTypeUserPasswordAuth {
						t.Fatalf("AuthFlow = %s, want USER_PASSWORD_AUTH", in.AuthFlow)
					}

					if in.AuthParameters["USERNAME"] != "alice" || in.AuthParameters["PASSWORD"] != "secret" {
						t.Fatalf("unexpected AuthParameters: %+v", in.AuthParameters)
					}

					return authResult("fresh-id", "fresh-access", "fresh-refresh", 3600), nil
				}}
			},
			wantToken: "fresh-id",
		},
		{
			name:      "access token kind",
			tokenKind: "access",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					return authResult("fresh-id", "fresh-access", "fresh-refresh", 3600), nil
				}}
			},
			wantToken: "fresh-access",
		},
		{
			name:      "unknown token kind errors",
			tokenKind: "bogus",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)

				cache := jwtCache{IDToken: "cached-id", IssuedAt: time.Now(), ExpiresIn: time.Hour}
				b, _ := json.Marshal(cache, json.WithMarshalers(durationToJS))     //nolint:errcheck // ok
				keyring.Set(jwtKeyringService, "p/pool1/client1/alice", string(b)) //nolint:errcheck,gosec // ok
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()
				return &mockCognitoClient{}
			},
			wantErr: true,
		},
		{
			name: "stale cache with valid refresh token skips password auth",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)

				cache := jwtCache{IDToken: "old-id", RefreshToken: "refresh-tok", IssuedAt: time.Now().Add(-2 * time.Hour), ExpiresIn: time.Hour}
				b, _ := json.Marshal(cache, json.WithMarshalers(durationToJS))     //nolint:errcheck // ok
				keyring.Set(jwtKeyringService, "p/pool1/client1/alice", string(b)) //nolint:errcheck,gosec // ok
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(_ context.Context, in *cip.InitiateAuthInput, _ ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					if in.AuthFlow != types.AuthFlowTypeRefreshTokenAuth {
						t.Fatalf("AuthFlow = %s, want REFRESH_TOKEN_AUTH", in.AuthFlow)
					}

					if in.AuthParameters["REFRESH_TOKEN"] != "refresh-tok" {
						t.Fatalf("unexpected AuthParameters: %+v", in.AuthParameters)
					}

					return authResult("refreshed-id", "refreshed-access", "", 3600), nil
				}}
			},
			wantToken: "refreshed-id",
		},
		{
			name: "stale cache with rejected refresh token falls back to password auth",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)

				cache := jwtCache{IDToken: "old-id", RefreshToken: "bad-tok", IssuedAt: time.Now().Add(-2 * time.Hour), ExpiresIn: time.Hour}
				b, _ := json.Marshal(cache, json.WithMarshalers(durationToJS))     //nolint:errcheck // ok
				keyring.Set(jwtKeyringService, "p/pool1/client1/alice", string(b)) //nolint:errcheck,gosec // ok
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(_ context.Context, in *cip.InitiateAuthInput, _ ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					if in.AuthFlow == types.AuthFlowTypeRefreshTokenAuth {
						return nil, &types.NotAuthorizedException{Message: new("Refresh Token has expired")}
					}

					return authResult("pw-id", "pw-access", "pw-refresh", 3600), nil
				}}
			},
			wantToken: "pw-id",
		},
		{
			name: "unconfigured pool bootstraps itself and its first user",
			prompt: func() func(string, *string) error {
				return func(label string, val *string) error {
					switch label {
					case "UserPoolId":
						*val = "newpool"
					case "ClientId":
						*val = "newclient"
					case "Password for bob":
						*val = "bobpass"
					default:
						panic("unexpected prompt: " + label)
					}

					return nil
				}
			}(),
			userFlag: "bob",
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(_ context.Context, in *cip.InitiateAuthInput, _ ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					if in.AuthParameters["USERNAME"] != "bob" || in.AuthParameters["PASSWORD"] != "bobpass" {
						t.Fatalf("unexpected AuthParameters: %+v", in.AuthParameters)
					}

					return authResult("bob-id", "bob-access", "bob-refresh", 3600), nil
				}}
			},
			wantToken: "bob-id",
		},
		{
			name: "challenge response is a hard error",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					return &cip.InitiateAuthOutput{ChallengeName: types.ChallengeNameTypeNewPasswordRequired}, nil
				}}
			},
			wantErr: true,
		},
		{
			name:     "ambiguous user prefix is a hard error, no cognito calls",
			userFlag: "a",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", CognitoPool{
					UserPoolID: "pool1", ClientID: "client1", DefaultUser: "alice",
					Users: []CognitoUser{{Username: "alice"}, {Username: "alex"}},
				})
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					t.Fatal("InitiateAuth should not be called on ambiguous user")
					return nil, nil
				}}
			},
			wantErr: true,
		},
		{
			name: "UserPoolId prompt error aborts before any cognito call",
			prompt: func(label string, val *string) error {
				if label != "UserPoolId" {
					return errors.New("unexpected prompt: " + label)
				}

				return errors.New("user aborted")
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					t.Fatal("InitiateAuth should not be called")
					return nil, nil
				}}
			},
			wantErr: true,
		},
		{
			name: "ClientId prompt error aborts before any cognito call",
			prompt: func(label string, val *string) error {
				switch label {
				case "UserPoolId":
					*val = "newpool"
					return nil
				case "ClientId":
					return errors.New("user aborted")
				default:
					return errors.New("unexpected prompt: " + label)
				}
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					t.Fatal("InitiateAuth should not be called")
					return nil, nil
				}}
			},
			wantErr: true,
		},
		{
			name: "empty authentication result with no challenge is a hard error",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", basePool)
			},
			cognito: func(t *testing.T) *mockCognitoClient {
				t.Helper()

				return &mockCognitoClient{initiateAuthFunc: func(context.Context, *cip.InitiateAuthInput, ...func(*cip.Options)) (*cip.InitiateAuthOutput, error) {
					return &cip.InitiateAuthOutput{}, nil
				}}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()

			if tt.setupFn != nil {
				tt.setupFn(t)
			}

			a := app{
				SkewPad:         120 * time.Second,
				prompt:          tt.prompt,
				mkCognitoClient: func() cognitoIdpAPI { return tt.cognito(t) },
			}
			if a.prompt == nil {
				a.prompt = func(string, *string) error { return errors.New("prompt not expected") }
			}

			got, err := a.jwt(t.Context(), "p", tt.userFlag, tt.tokenKind)
			if (err != nil) != tt.wantErr {
				t.Fatalf("jwt() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if got != tt.wantToken {
				t.Errorf("jwt() = %q, want %q", got, tt.wantToken)
			}
		})
	}
}

func TestAppAddCognitoUser(t *testing.T) { //nolint:funlen // ok
	tests := []struct {
		setupFn func(t *testing.T)
		prompt  func(string, *string) error
		name    string
		wantErr bool
	}{
		{
			name: "adds a second user without touching the existing default",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", CognitoPool{
					UserPoolID: "pool1", ClientID: "client1", DefaultUser: "alice",
					Users: []CognitoUser{{Username: "alice", Password: "secret"}},
				})
			},
			prompt: func() func(string, *string) error {
				calls := 0

				return func(label string, val *string) error {
					calls++
					switch calls {
					case 1:
						if label != "Username" {
							t.Fatalf("unexpected prompt label %q", label)
						}

						*val = "bob"
					case 2:
						if label != "Password for bob" {
							t.Fatalf("unexpected prompt label %q", label)
						}

						*val = "bobpass"
					}

					return nil
				}
			}(),
		},
		{
			name: "duplicate username is a hard error",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", CognitoPool{
					UserPoolID: "pool1", ClientID: "client1", DefaultUser: "alice",
					Users: []CognitoUser{{Username: "alice", Password: "secret"}},
				})
			},
			prompt: func(_ string, val *string) error {
				*val = "alice"
				return nil
			},
			wantErr: true,
		},
		{
			name:    "unconfigured pool is a hard error",
			setupFn: func(t *testing.T) { t.Helper() },
			prompt: func(string, *string) error {
				t.Fatal("prompt should not be called")
				return nil
			},
			wantErr: true,
		},
		{
			name: "username prompt error propagates",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", CognitoPool{
					UserPoolID: "pool1", ClientID: "client1", DefaultUser: "alice",
					Users: []CognitoUser{{Username: "alice", Password: "secret"}},
				})
			},
			prompt: func(string, *string) error {
				return errors.New("aborted")
			},
			wantErr: true,
		},
		{
			name: "password prompt error propagates",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", CognitoPool{
					UserPoolID: "pool1", ClientID: "client1", DefaultUser: "alice",
					Users: []CognitoUser{{Username: "alice", Password: "secret"}},
				})
			},
			prompt: func() func(string, *string) error {
				calls := 0

				return func(_ string, val *string) error {
					calls++
					if calls == 1 {
						*val = "bob"
						return nil
					}

					return errors.New("aborted")
				}
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn(t)

			a := app{prompt: tt.prompt}

			err := a.addCognitoUser("p")
			if (err != nil) != tt.wantErr {
				t.Fatalf("addCognitoUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAppSetDefaultCognitoUser(t *testing.T) { //nolint:funlen // ok
	basePool := CognitoPool{
		UserPoolID: "pool1", ClientID: "client1", DefaultUser: "alice",
		Users: []CognitoUser{{Username: "alice", Password: "p1"}, {Username: "bob", Password: "p2"}},
	}

	tests := []struct {
		setupFn     func(t *testing.T)
		prompt      func(string, *string) error
		name        string
		userFlag    string
		wantDefault string
		wantErr     bool
	}{
		{
			name:        "switches default to an unambiguous prefix match",
			userFlag:    "bob",
			setupFn:     func(t *testing.T) { t.Helper(); setCognitoPool(t, "p", basePool) },
			wantDefault: "bob",
		},
		{
			name:     "unknown user is a hard error, does not create one",
			userFlag: "carol",
			setupFn:  func(t *testing.T) { t.Helper(); setCognitoPool(t, "p", basePool) },
			wantErr:  true,
		},
		{
			name:    "unconfigured pool is a hard error",
			setupFn: func(t *testing.T) { t.Helper() },
			wantErr: true,
		},
		{
			name:     "ambiguous prefix is a hard error",
			userFlag: "a",
			setupFn: func(t *testing.T) {
				t.Helper()
				setCognitoPool(t, "p", CognitoPool{
					UserPoolID: "pool1", ClientID: "client1", DefaultUser: "alice",
					Users: []CognitoUser{{Username: "alice"}, {Username: "alex"}},
				})
			},
			wantErr: true,
		},
		{
			name:        "dash prompts for a username then resolves it",
			userFlag:    "-",
			setupFn:     func(t *testing.T) { t.Helper(); setCognitoPool(t, "p", basePool) },
			prompt:      func(_ string, val *string) error { *val = "bob"; return nil },
			wantDefault: "bob",
		},
		{
			name:     "prompt error propagates",
			userFlag: "-",
			setupFn:  func(t *testing.T) { t.Helper(); setCognitoPool(t, "p", basePool) },
			prompt: func(string, *string) error {
				return errors.New("aborted")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn(t)

			a := app{prompt: tt.prompt}

			err := a.setDefaultCognitoUser("p", tt.userFlag)
			if (err != nil) != tt.wantErr {
				t.Fatalf("setDefaultCognitoUser() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			var pool CognitoPool

			if err = pool.load("p"); err != nil {
				t.Fatalf("reload failed: %v", err)
			}

			if pool.DefaultUser != tt.wantDefault {
				t.Errorf("DefaultUser = %q, want %q", pool.DefaultUser, tt.wantDefault)
			}
		})
	}
}

func TestStrOrEmpty(t *testing.T) {
	if got := strOrEmpty(nil); got != "" {
		t.Errorf("strOrEmpty(nil) = %q, want empty", got)
	}

	s := "hi"
	if got := strOrEmpty(&s); got != "hi" {
		t.Errorf("strOrEmpty(&s) = %q, want %q", got, s)
	}
}

func setCognitoPool(t *testing.T, poolName string, pool CognitoPool) { //nolint:unparam // ok
	t.Helper()

	b, err := json.Marshal(pool)
	if err != nil {
		t.Fatalf("marshal pool: %v", err)
	}

	if err = keyring.Set(cognitoKeyringService, poolName, string(b)); err != nil {
		t.Fatalf("set pool: %v", err)
	}
}

func authResult(idToken, accessToken, refreshToken string, expiresIn int32) *cip.InitiateAuthOutput { //nolint:unparam // ok
	return &cip.InitiateAuthOutput{
		AuthenticationResult: &types.AuthenticationResultType{
			IdToken:      &idToken,
			AccessToken:  &accessToken,
			RefreshToken: &refreshToken,
			ExpiresIn:    expiresIn,
		},
	}
}
