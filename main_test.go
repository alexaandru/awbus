//nolint:lll // ok
package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iam_types "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/zalando/go-keyring"
)

type mockSTSClient struct {
	assumeRoleFunc func(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type mockIAMClient struct {
	createAccessKeyFunc func(context.Context, *iam.CreateAccessKeyInput, ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	deleteAccessKeyFunc func(context.Context, *iam.DeleteAccessKeyInput, ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}

func (m *mockSTSClient) AssumeRole(ctx context.Context, input *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return m.assumeRoleFunc(ctx, input, opts...)
}

func (m *mockIAMClient) CreateAccessKey(ctx context.Context, input *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	return m.createAccessKeyFunc(ctx, input, opts...)
}

func (m *mockIAMClient) DeleteAccessKey(ctx context.Context, input *iam.DeleteAccessKeyInput, opts ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	return m.deleteAccessKeyFunc(ctx, input, opts...)
}

func TestNewApp(t *testing.T) { //nolint:funlen // ok
	tests := []struct {
		name        string
		envVars     map[string]string
		iamClient   iamAPI
		wantRegion  string
		wantProfile string
		wantTTL     time.Duration
		wantPad     time.Duration
		wantErr     bool
	}{
		{
			name: "with mock iam client",
			envVars: map[string]string{
				"AWS_REGION":  "eu-west-1",
				"AWS_PROFILE": "custom",
				"SESSION_TTL": "7200s",
				"SKEW_PAD":    "300s",
			},
			iamClient: &mockIAMClient{
				createAccessKeyFunc: func(ctx context.Context, input *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
					return &iam.CreateAccessKeyOutput{}, nil
				},
				deleteAccessKeyFunc: func(ctx context.Context, input *iam.DeleteAccessKeyInput, opts ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
					return &iam.DeleteAccessKeyOutput{}, nil
				},
			},
			wantRegion:  "eu-west-1",
			wantProfile: "custom",
			wantTTL:     7200 * time.Second,
			wantPad:     300 * time.Second,
		},
		{
			name: "defaults with mock iam",
			envVars: map[string]string{
				"AWS_PROFILE": "testdefault",
			},
			iamClient: &mockIAMClient{
				createAccessKeyFunc: func(ctx context.Context, input *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
					return &iam.CreateAccessKeyOutput{}, nil
				},
				deleteAccessKeyFunc: func(ctx context.Context, input *iam.DeleteAccessKeyInput, opts ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
					return &iam.DeleteAccessKeyOutput{}, nil
				},
			},
			wantRegion:  defaultRegion,
			wantProfile: "testdefault",
			wantTTL:     defaultSessionTTL,
			wantPad:     defaultSkewPad,
		},
		{
			name: "confetti load error",
			envVars: map[string]string{
				"SESSION_TTL": "invalid",
			},
			iamClient: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			a, err := newApp(tt.iamClient) //nolint:varnamelen // ok
			if (err != nil) != tt.wantErr {
				t.Errorf("newApp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if a.AWSRegion != tt.wantRegion {
				t.Errorf("AWSRegion = %s, want %s", a.AWSRegion, tt.wantRegion)
			}

			if a.AWSProfile != tt.wantProfile {
				t.Errorf("AWSProfile = %s, want %s", a.AWSProfile, tt.wantProfile)
			}

			if a.SessionTTL != tt.wantTTL {
				t.Errorf("SessionTTL = %v, want %v", a.SessionTTL, tt.wantTTL)
			}

			if a.SkewPad != tt.wantPad {
				t.Errorf("SkewPad = %v, want %v", a.SkewPad, tt.wantPad)
			}

			if a.iamAPI == nil {
				t.Error("iamAPI should not be nil")
			}
		})
	}
}

func TestKrGet(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		setupFn func()
		wantVal string
		wantErr bool
	}{
		{
			name:    "existing key",
			profile: "test-profile",
			setupFn: func() {
				keyring.Set(keyringService, "test-profile", "test-value") //nolint:errcheck,gosec // ok
			},
			wantVal: "test-value",
		},
		{
			name:    "nonexistent key",
			profile: "nonexistent",
			setupFn: func() {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn()

			got, err := krGet(tt.profile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("krGet() error = %v, wantErr %v", err, tt.wantErr)
			}

			if got != tt.wantVal {
				t.Errorf("krGet() = %s, want %s", got, tt.wantVal)
			}
		})
	}
}

func TestKrSet(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		value   string
		wantErr bool
	}{
		{
			name:    "valid set",
			profile: "test-profile",
			value:   "test-value",
		},
		{
			name:    "empty value",
			profile: "empty-profile",
			value:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()

			err := krSet(tt.profile, tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("krSet() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				var got string

				got, err = keyring.Get(keyringService, tt.profile)
				if err != nil {
					t.Errorf("verification failed: %v", err)
				}

				if got != tt.value {
					t.Errorf("stored value = %s, want %s", got, tt.value)
				}
			}
		})
	}
}

func TestKrDel(t *testing.T) {
	tests := []struct {
		setupFn func()
		name    string
		profile string
		wantErr bool
	}{
		{
			name:    "existing key",
			profile: "delete-me",
			setupFn: func() {
				keyring.Set(keyringService, "delete-me", "value") //nolint:errcheck,gosec // ok
			},
		},
		{
			name:    "nonexistent key",
			profile: "nonexistent",
			setupFn: func() {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn()

			err := krDel(tt.profile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("krDel() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				_, err = keyring.Get(keyringService, tt.profile)
				if err == nil {
					t.Error("key still exists after deletion")
				}
			}
		})
	}
}

func TestCredsLoad(t *testing.T) { //nolint:funlen // ok
	validCreds := Creds{
		Version:         1,
		AccessKeyID:     "AKIA123",
		SecretAccessKey: "secret123",
	}
	validJSON, _ := json.Marshal(validCreds) //nolint:errcheck // ok
	tests := []struct {
		name     string
		profile  string
		setupFn  func()
		wantCred Creds
		wantErr  bool
	}{
		{
			name:    "valid JSON",
			profile: "valid",
			setupFn: func() {
				keyring.Set(keyringService, "valid", string(validJSON)) //nolint:errcheck,gosec // ok
			},
			wantCred: validCreds,
		},
		{
			name:    "nonexistent profile",
			profile: "nonexistent",
			setupFn: func() {},
			wantErr: true,
		},
		{
			name:    "empty JSON",
			profile: "empty",
			setupFn: func() {
				keyring.Set(keyringService, "empty", "") //nolint:errcheck,gosec // ok
			},
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			profile: "invalid",
			setupFn: func() {
				keyring.Set(keyringService, "invalid", "not json") //nolint:errcheck,gosec // ok
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn()

			var c Creds

			err := c.load(tt.profile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("load() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				if c.AccessKeyID != tt.wantCred.AccessKeyID {
					t.Errorf("AccessKeyID = %s, want %s", c.AccessKeyID, tt.wantCred.AccessKeyID)
				}

				if c.SecretAccessKey != tt.wantCred.SecretAccessKey {
					t.Errorf("SecretAccessKey = %s, want %s", c.SecretAccessKey, tt.wantCred.SecretAccessKey)
				}
			}
		})
	}
}

func TestCredsStore(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		creds   Creds
		wantErr bool
	}{
		{
			name: "valid credentials",
			creds: Creds{
				AccessKeyID:     "AKIA456",
				SecretAccessKey: "secret456",
			},
			profile: "test-store",
		},
		{
			name: "with session data",
			creds: Creds{
				AccessKeyID:     "ASIA789",
				SecretAccessKey: "secret789",
				SessionToken:    "token789",
				RoleArn:         "arn:aws:iam::123:role/test",
			},
			profile: "role-store",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()

			err := tt.creds.store(tt.profile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("store() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				var stored string

				stored, err = keyring.Get(keyringService, tt.profile)
				if err != nil {
					t.Fatalf("keyring.Get() error = %v", err)
				}

				var retrieved Creds

				err = json.Unmarshal([]byte(stored), &retrieved)
				if err != nil {
					t.Fatalf("json.Unmarshal() error = %v", err)
				}

				if retrieved.Version != 1 {
					t.Errorf("Version = %d, want 1", retrieved.Version)
				}

				if retrieved.AccessKeyID != tt.creds.AccessKeyID {
					t.Errorf("AccessKeyID = %s, want %s", retrieved.AccessKeyID, tt.creds.AccessKeyID)
				}
			}
		})
	}
}

func TestCredsApplyDefaults(t *testing.T) { //nolint:funlen // ok
	tests := []struct {
		name    string
		creds   Creds
		cfg     config
		wantTTL time.Duration
		wantPad time.Duration
	}{
		{
			name:  "empty creds with config",
			creds: Creds{},
			cfg: config{
				SkewPad:    300 * time.Second,
				SessionTTL: 7200 * time.Second,
			},
			wantTTL: 7200 * time.Second,
			wantPad: 300 * time.Second,
		},
		{
			name: "existing values preserved",
			creds: Creds{
				SkewPad:    600 * time.Second,
				SessionTTL: 1800 * time.Second,
			},
			cfg: config{
				SkewPad:    300 * time.Second,
				SessionTTL: 7200 * time.Second,
			},
			wantTTL: 1800 * time.Second,
			wantPad: 600 * time.Second,
		},
		{
			name:  "TTL limits applied",
			creds: Creds{},
			cfg: config{
				SessionTTL: 24 * time.Hour,
			},
			wantTTL: maxAllowedSessionTTL,
			wantPad: 0,
		},
		{
			name:  "minimum TTL enforced",
			creds: Creds{},
			cfg: config{
				SessionTTL: 5 * time.Minute,
			},
			wantTTL: minAllowedSessionTTL,
			wantPad: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.creds.applyDefaults(tt.cfg)

			if tt.creds.SessionTTL != tt.wantTTL {
				t.Errorf("SessionTTL = %v, want %v", tt.creds.SessionTTL, tt.wantTTL)
			}

			if tt.creds.SkewPad != tt.wantPad {
				t.Errorf("SkewPad = %v, want %v", tt.creds.SkewPad, tt.wantPad)
			}
		})
	}
}

func TestCredsIsStatic(t *testing.T) {
	tests := []struct {
		name  string
		creds Creds
		want  bool
	}{
		{
			name:  "no role arn",
			creds: Creds{AccessKeyID: "AKIA123"},
			want:  true,
		},
		{
			name:  "with role arn",
			creds: Creds{RoleArn: "arn:aws:iam::123:role/test"},
			want:  false,
		},
		{
			name:  "empty creds",
			creds: Creds{},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.creds.isStatic(); got != tt.want {
				t.Errorf("isStatic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCredsValidateStatic(t *testing.T) {
	tests := []struct {
		name    string
		creds   Creds
		wantErr bool
	}{
		{
			name: "valid static",
			creds: Creds{
				AccessKeyID:     "AKIA123",
				SecretAccessKey: "secret123",
			},
		},
		{
			name: "has role arn",
			creds: Creds{
				RoleArn:         "arn:aws:iam::123:role/test",
				AccessKeyID:     "AKIA123",
				SecretAccessKey: "secret123",
			},
			wantErr: true,
		},
		{
			name: "missing access key",
			creds: Creds{
				SecretAccessKey: "secret123",
			},
			wantErr: true,
		},
		{
			name: "missing secret key",
			creds: Creds{
				AccessKeyID: "AKIA123",
			},
			wantErr: true,
		},
		{
			name: "has expiration",
			creds: Creds{
				AccessKeyID:     "AKIA123",
				SecretAccessKey: "secret123",
				Expiration:      time.Now(),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.creds.validateStatic()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateStatic() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCredsCredsFresh(t *testing.T) {
	now := time.Now()
	skewPad := 5 * time.Minute

	tests := []struct {
		now   time.Time
		name  string
		creds Creds
		want  bool
	}{
		{
			name:  "static creds always fresh",
			creds: Creds{},
			now:   now,
			want:  true,
		},
		{
			name: "fresh role creds",
			creds: Creds{
				RoleArn:    "arn:aws:iam::123:role/test",
				Expiration: now.Add(10 * time.Minute),
				SkewPad:    skewPad,
			},
			now:  now,
			want: true,
		},
		{
			name: "expired role creds",
			creds: Creds{
				RoleArn:    "arn:aws:iam::123:role/test",
				Expiration: now.Add(2 * time.Minute),
				SkewPad:    skewPad,
			},
			now:  now,
			want: false,
		},
		{
			name: "no expiration set",
			creds: Creds{
				RoleArn: "arn:aws:iam::123:role/test",
				SkewPad: skewPad,
			},
			now:  now,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.creds.credsFresh(tt.now); got != tt.want {
				t.Errorf("credsFresh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCredsEmitProfile(t *testing.T) {
	tests := []struct {
		name    string
		creds   Creds
		wantErr bool
	}{
		{
			name: "static credentials",
			creds: Creds{
				Version:         1,
				AccessKeyID:     "AKIA123",
				SecretAccessKey: "secret123",
			},
		},
		{
			name: "role credentials",
			creds: Creds{
				Version:         1,
				AccessKeyID:     "ASIA456",
				SecretAccessKey: "tempsecret",
				SessionToken:    "token123",
				Expiration:      time.Now().Add(time.Hour),
				RoleArn:         "arn:aws:iam::123:role/test",
				SourceProfile:   "base",
				SessionTTL:      3600 * time.Second,
				SkewPad:         120 * time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.creds.emitProfile()
			if (err != nil) != tt.wantErr {
				t.Errorf("emitProfile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAppAssumeRole(t *testing.T) { //nolint:funlen // ok
	expiration := time.Now().Add(time.Hour)

	tests := []struct {
		mockSTS     *mockSTSClient
		name        string
		wantKeyID   string
		baseCreds   Creds
		targetCreds Creds
		wantErr     bool
	}{
		{
			name: "successful assume role",
			mockSTS: &mockSTSClient{
				assumeRoleFunc: func(ctx context.Context, input *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{
						Credentials: &types.Credentials{
							AccessKeyId:     aws.String("ASIA123"),
							SecretAccessKey: aws.String("tempsecret"),
							SessionToken:    aws.String("token123"),
							Expiration:      &expiration,
						},
					}, nil
				},
			},
			baseCreds: Creds{
				AccessKeyID:     "AKIA123",
				SecretAccessKey: "secret123",
			},
			targetCreds: Creds{
				RoleArn:       "arn:aws:iam::123:role/test",
				SourceProfile: "base",
				SessionTTL:    3600 * time.Second,
			},
			wantKeyID: "ASIA123",
		},
		{
			name: "STS error",
			mockSTS: &mockSTSClient{
				assumeRoleFunc: func(ctx context.Context, input *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return nil, errors.New("access denied")
				},
			},
			baseCreds:   Creds{AccessKeyID: "AKIA123", SecretAccessKey: "secret123"},
			targetCreds: Creds{RoleArn: "arn:aws:iam::123:role/test"},
			wantErr:     true,
		},
		{
			name: "nil credentials",
			mockSTS: &mockSTSClient{
				assumeRoleFunc: func(ctx context.Context, input *sts.AssumeRoleInput, opts ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
					return &sts.AssumeRoleOutput{Credentials: nil}, nil
				},
			},
			baseCreds:   Creds{AccessKeyID: "AKIA123", SecretAccessKey: "secret123"},
			targetCreds: Creds{RoleArn: "arn:aws:iam::123:role/test"},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			a := app{
				mkSTSClient: func(aws.CredentialsProvider) stsAPI { return tt.mockSTS },
			}

			result, err := a.assumeRole(ctx, tt.baseCreds, tt.targetCreds)
			if (err != nil) != tt.wantErr {
				t.Fatalf("assumeRole() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && result.AccessKeyID != tt.wantKeyID {
				t.Errorf("AccessKeyID = %s, want %s", result.AccessKeyID, tt.wantKeyID)
			}
		})
	}
}

func TestAppResolveAndMaybeRefresh(t *testing.T) { //nolint:funlen // ok
	staticCreds := Creds{
		Version:         1,
		AccessKeyID:     "AKIA123",
		SecretAccessKey: "secret123",
	}
	staticJSON, _ := json.Marshal(staticCreds) //nolint:errcheck // ok
	baseCreds := Creds{
		Version:         1,
		AccessKeyID:     "AKIA456",
		SecretAccessKey: "secret456",
	}
	baseJSON, _ := json.Marshal(baseCreds) //nolint:errcheck // ok
	expiration := time.Now().Add(time.Hour)
	roleCreds := Creds{
		Version:         1,
		RoleArn:         "arn:aws:iam::123:role/test",
		SourceProfile:   "base-profile",
		AccessKeyID:     "ASIA789",
		SecretAccessKey: "tempsecret",
		SessionToken:    "token123",
		Expiration:      expiration,
	}
	roleJSON, _ := json.Marshal(roleCreds) //nolint:errcheck // ok
	tests := []struct {
		name      string
		profile   string
		setupFn   func()
		app       app
		wantKeyID string
		wantErr   bool
	}{
		{
			name:    "static profile",
			profile: "static-profile",
			setupFn: func() {
				keyring.Set(keyringService, "static-profile", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			app: app{
				config: config{
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
			wantKeyID: "AKIA123",
		},
		{
			name:    "fresh role profile",
			profile: "role-profile",
			setupFn: func() {
				keyring.Set(keyringService, "base-profile", string(baseJSON)) //nolint:errcheck,gosec // ok
				keyring.Set(keyringService, "role-profile", string(roleJSON)) //nolint:errcheck,gosec // ok
			},
			app: app{
				config: config{
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
			wantKeyID: "ASIA789",
		},
		{
			name:    "nonexistent profile",
			profile: "nonexistent",
			setupFn: func() {},
			app:     app{},
			wantErr: true,
		},
		{
			name:    "role missing source profile",
			profile: "missing-source",
			setupFn: func() {
				missingSourceCreds := Creds{
					Version: 1,
					RoleArn: "arn:aws:iam::123:role/test",
				}
				missingJSON, _ := json.Marshal(missingSourceCreds)                 //nolint:errcheck // ok
				keyring.Set(keyringService, "missing-source", string(missingJSON)) //nolint:errcheck,gosec // ok
			},
			app: app{
				config: config{
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name:    "nonexistent source profile",
			profile: "bad-source",
			setupFn: func() {
				badSourceCreds := Creds{
					Version:       1,
					RoleArn:       "arn:aws:iam::123:role/test",
					SourceProfile: "nonexistent-source",
				}
				badJSON, _ := json.Marshal(badSourceCreds)                 //nolint:errcheck // ok
				keyring.Set(keyringService, "bad-source", string(badJSON)) //nolint:errcheck,gosec // ok
			},
			app: app{
				config: config{
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name:    "non-static source profile",
			profile: "nested-role",
			setupFn: func() {
				nestedSourceCreds := Creds{
					Version:       1,
					RoleArn:       "arn:aws:iam::123:role/source",
					SourceProfile: "another-role",
				}
				nestedJSON, _ := json.Marshal(nestedSourceCreds)                 //nolint:errcheck // ok
				keyring.Set(keyringService, "nested-source", string(nestedJSON)) //nolint:errcheck,gosec // ok

				nestedRoleCreds := Creds{
					Version:       1,
					RoleArn:       "arn:aws:iam::123:role/target",
					SourceProfile: "nested-source",
				}
				nestedRoleJSON, _ := json.Marshal(nestedRoleCreds)                 //nolint:errcheck // ok
				keyring.Set(keyringService, "nested-role", string(nestedRoleJSON)) //nolint:errcheck,gosec // ok//
			},
			app: app{
				config: config{
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name:    "invalid source profile",
			profile: "invalid-source",
			setupFn: func() {
				invalidSource := Creds{
					Version:         1,
					AccessKeyID:     "AKIA123",
					SecretAccessKey: "secret123",
					Expiration:      time.Now(),
				}
				invalidJSON, _ := json.Marshal(invalidSource)                           //nolint:errcheck // ok
				keyring.Set(keyringService, "invalid-source-base", string(invalidJSON)) //nolint:errcheck,gosec // ok

				roleCreds2 := Creds{
					Version:       1,
					RoleArn:       "arn:aws:iam::123:role/test",
					SourceProfile: "invalid-source-base",
				}
				roleJSON2, _ := json.Marshal(roleCreds2)                         //nolint:errcheck // ok
				keyring.Set(keyringService, "invalid-source", string(roleJSON2)) //nolint:errcheck,gosec // ok
			},
			app: app{
				config: config{
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn()

			ctx := t.Context()

			result, err := tt.app.resolveAndMaybeRefresh(ctx, tt.profile)
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveAndMaybeRefresh() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && result.AccessKeyID != tt.wantKeyID {
				t.Errorf("AccessKeyID = %s, want %s", result.AccessKeyID, tt.wantKeyID)
			}
		})
	}
}

func TestAppRotateCredentials(t *testing.T) { //nolint:funlen // ok
	staticCreds := Creds{
		Version:         1,
		AccessKeyID:     "AKIA123",
		SecretAccessKey: "secret123",
	}
	staticJSON, _ := json.Marshal(staticCreds) //nolint:errcheck // ok
	roleCreds := Creds{
		Version:       1,
		RoleArn:       "arn:aws:iam::123:role/test",
		SourceProfile: "base",
	}
	roleJSON, _ := json.Marshal(roleCreds) //nolint:errcheck // ok
	tests := []struct {
		setupFn func()
		mockIAM *mockIAMClient
		name    string
		profile string
		wantErr bool
	}{
		{
			name:    "successful rotation",
			profile: "rotate-profile",
			setupFn: func() {
				keyring.Set(keyringService, "rotate-profile", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			mockIAM: &mockIAMClient{
				createAccessKeyFunc: func(ctx context.Context, input *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
					return &iam.CreateAccessKeyOutput{
						AccessKey: &iam_types.AccessKey{
							AccessKeyId:     aws.String("AKIA456"),
							SecretAccessKey: aws.String("newsecret456"),
						},
					}, nil
				},
				deleteAccessKeyFunc: func(ctx context.Context, input *iam.DeleteAccessKeyInput, opts ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
					return &iam.DeleteAccessKeyOutput{}, nil
				},
			},
		},
		{
			name:    "non-static profile",
			profile: "role-profile",
			setupFn: func() {
				keyring.Set(keyringService, "role-profile", string(roleJSON)) //nolint:errcheck,gosec // ok
			},
			mockIAM: &mockIAMClient{},
			wantErr: true,
		},
		{
			name:    "nonexistent profile",
			profile: "nonexistent",
			setupFn: func() {},
			mockIAM: &mockIAMClient{},
			wantErr: true,
		},
		{
			name:    "IAM create error",
			profile: "create-error",
			setupFn: func() {
				keyring.Set(keyringService, "create-error", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			mockIAM: &mockIAMClient{
				createAccessKeyFunc: func(ctx context.Context, input *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
					return nil, errors.New("IAM create failed")
				},
			},
			wantErr: true,
		},
		{
			name:    "nil access key response",
			profile: "nil-key",
			setupFn: func() {
				keyring.Set(keyringService, "nil-key", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			mockIAM: &mockIAMClient{
				createAccessKeyFunc: func(ctx context.Context, input *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
					return &iam.CreateAccessKeyOutput{AccessKey: nil}, nil
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn()

			a := app{iamAPI: tt.mockIAM}

			err := a.rotateCredentials(t.Context(), tt.profile)
			if (err != nil) != tt.wantErr {
				t.Errorf("rotateCredentials() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAppRun(t *testing.T) { //nolint:funlen // ok
	staticCreds := Creds{
		Version:         1,
		AccessKeyID:     "AKIA123",
		SecretAccessKey: "secret123",
	}
	staticJSON, _ := json.Marshal(staticCreds) //nolint:errcheck // ok
	tests := []struct {
		app        app
		setupFn    func()
		mockPrompt func(string, *string) error
		mockIAM    *mockIAMClient
		name       string
		args       []string
		wantErr    bool
	}{
		{
			name: "load command",
			args: []string{"awbus", "load"},
			setupFn: func() {
				keyring.Set(keyringService, "test-profile", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			app: app{
				config: config{
					AWSProfile: "test-profile",
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
		},
		{
			name: "default load",
			args: []string{"awbus"},
			setupFn: func() {
				keyring.Set(keyringService, "default-profile", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			app: app{
				config: config{
					AWSProfile: "default-profile",
					SkewPad:    120 * time.Second,
					SessionTTL: 3600 * time.Second,
				},
			},
		},
		{
			name: "rotate command",
			args: []string{"awbus", "rotate"},
			setupFn: func() {
				keyring.Set(keyringService, "rotate-profile", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			mockIAM: &mockIAMClient{
				createAccessKeyFunc: func(ctx context.Context, input *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
					return &iam.CreateAccessKeyOutput{
						AccessKey: &iam_types.AccessKey{
							AccessKeyId:     aws.String("AKIA789"),
							SecretAccessKey: aws.String("newsecret789"),
						},
					}, nil
				},
				deleteAccessKeyFunc: func(ctx context.Context, input *iam.DeleteAccessKeyInput, opts ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
					return &iam.DeleteAccessKeyOutput{}, nil
				},
			},
			app: app{
				config: config{AWSProfile: "rotate-profile"},
			},
		},
		{
			name:    "store command",
			args:    []string{"awbus", "store"},
			setupFn: func() {},
			mockPrompt: func(label string, val *string) error {
				switch label {
				case "Profile Name (press Enter for 'default')":
					*val = "new-profile"
				case "AccessKeyId":
					*val = "AKIA999"
				case "SecretAccessKey":
					*val = "secret999"
				}

				return nil
			},
			app: app{
				config: config{AWSProfile: "default"},
			},
		},
		{
			name:    "store-assume command",
			args:    []string{"awbus", "store-assume"},
			setupFn: func() {},
			mockPrompt: func(label string, val *string) error {
				switch label {
				case "Profile Name (press Enter for 'default')":
					*val = "assume-profile"
				case "RoleArn":
					*val = "arn:aws:iam::123:role/test"
				case "SourceProfile":
					*val = "base-profile"
				}

				return nil
			},
			app: app{
				config: config{AWSProfile: "default"},
			},
		},
		{
			name: "delete command",
			args: []string{"awbus", "delete"},
			setupFn: func() {
				keyring.Set(keyringService, "delete-me", "test-data") //nolint:errcheck,gosec // ok
			},
			mockPrompt: func(label string, val *string) error {
				return errors.New("user pressed enter")
			},
			app: app{
				config: config{AWSProfile: "delete-me"},
			},
		},
		{
			name:    "version command",
			args:    []string{"awbus", "version"},
			setupFn: func() {},
			app:     app{},
		},
		{
			name:    "help command",
			args:    []string{"awbus", "help"},
			setupFn: func() {},
			app:     app{},
		},
		{
			name:    "unknown command",
			args:    []string{"awbus", "unknown"},
			setupFn: func() {},
			app:     app{},
			wantErr: true,
		},
		{
			name:    "store prompt error",
			args:    []string{"awbus", "store"},
			setupFn: func() {},
			mockPrompt: func(label string, val *string) error {
				return errors.New("prompt failed")
			},
			app: app{
				config: config{AWSProfile: "default"},
			},
			wantErr: true,
		},
		{
			name:    "store-assume prompt error",
			args:    []string{"awbus", "store-assume"},
			setupFn: func() {},
			mockPrompt: func(label string, val *string) error {
				if label == "RoleArn" {
					return errors.New("prompt failed")
				}

				*val = "test"

				return nil
			},
			app: app{
				config: config{AWSProfile: "default"},
			},
			wantErr: true,
		},
		{
			name: "delete abort",
			args: []string{"awbus", "delete"},
			setupFn: func() {
				keyring.Set(keyringService, "abort-delete", "test-data") //nolint:errcheck,gosec // ok
			},
			mockPrompt: func(label string, val *string) error {
				*val = "abort"
				return nil
			},
			app: app{
				config: config{AWSProfile: "abort-delete"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn()

			ctx := t.Context()

			if tt.mockPrompt != nil {
				tt.app.prompt = tt.mockPrompt
			}

			if tt.mockIAM != nil {
				tt.app.iamAPI = tt.mockIAM
			}

			err := tt.app.run(ctx, tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestP(t *testing.T) {
	tests := []struct {
		value any
		name  string
	}{
		{name: "string", value: "test"},
		{name: "int", value: 42},
		{name: "bool", value: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ptr := p(tt.value)
			if ptr == nil {
				t.Fatal("p() returned nil")
			}

			if *ptr != tt.value {
				t.Errorf("*p() = %v, want %v", *ptr, tt.value)
			}
		})
	}
}

func TestMain(t *testing.T) {
	t.Skip("Cannot easily test main() without complex mocking of os.Exit and newApp")
}

func TestDie(t *testing.T) {
	tests := []struct {
		err  error
		name string
		msg  string
	}{
		{
			name: "no error does nothing",
			msg:  "test message",
			err:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			die(tt.msg, tt.err)
		})
	}
}

func TestPrompt(t *testing.T) {
	tests := []struct {
		name    string
		label   string
		input   string
		wantVal string
		wantErr bool
	}{
		{
			name:    "valid input",
			label:   "test label",
			input:   "test-value\n",
			wantVal: "test-value",
		},
		{
			name:    "empty input causes error",
			label:   "test label",
			input:   "\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("failed to create pipe: %v", err)
			}
			defer r.Close() //nolint:errcheck // ok
			defer w.Close() //nolint:errcheck // ok

			oldStdin := os.Stdin

			defer func() { os.Stdin = oldStdin }()

			os.Stdin = r

			go func() {
				defer w.Close() //nolint:errcheck // ok

				w.WriteString(tt.input) //nolint:errcheck,gosec // ok
			}()

			var result string

			err = prompt(tt.label, &result)
			if (err != nil) != tt.wantErr {
				t.Fatalf("prompt() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && result != tt.wantVal {
				t.Errorf("prompt() result = %s, want %s", result, tt.wantVal)
			}
		})
	}
}
