package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zalando/go-keyring"
)

type mockSTSClient struct {
	assumeRoleFunc func(context.Context, *sts.AssumeRoleInput, ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

type mockPresignClient struct {
	presignFunc func(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

func (m *mockPresignClient) PresignGetCallerIdentity(ctx context.Context, input *sts.GetCallerIdentityInput, opts ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	return m.presignFunc(ctx, input, opts...)
}

func TestAppResolveSTSURL(t *testing.T) { //nolint:funlen // ok
	staticCreds := Creds{Version: 1, AccessKeyID: "AKIA123", SecretAccessKey: "secret123"}
	staticJSON, _ := json.Marshal(staticCreds) //nolint:errcheck // ok

	freshMock := func(t *testing.T) *mockPresignClient {
		t.Helper()

		return &mockPresignClient{
			presignFunc: func(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
				t.Fatal("presign should not be called for a fresh cached URL")
				return nil, nil
			},
		}
	}

	tests := []struct {
		name        string
		profile     string
		setupFn     func()
		presign     func(t *testing.T) *mockPresignClient
		wantURL     string
		wantErr     bool
		checkCached bool
	}{
		{
			name:    "fresh cache is reused without presigning",
			profile: "static-profile",
			setupFn: func() {
				keyring.Set(keyringService, "static-profile", string(staticJSON)) //nolint:errcheck,gosec // ok

				cache := stsURLCache{URL: "https://sts.amazonaws.com/?cached=1", IssuedAt: time.Now()}
				b, _ := json.Marshal(cache)                                    //nolint:errcheck // ok
				keyring.Set(stsURLKeyringService, "static-profile", string(b)) //nolint:errcheck,gosec // ok
			},
			presign: freshMock,
			wantURL: "https://sts.amazonaws.com/?cached=1",
		},
		{
			name:    "no cache presigns and stores a new URL",
			profile: "static-profile",
			setupFn: func() {
				keyring.Set(keyringService, "static-profile", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			presign: func(t *testing.T) *mockPresignClient {
				t.Helper()

				return &mockPresignClient{
					presignFunc: func(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
						return &v4.PresignedHTTPRequest{URL: "https://sts.amazonaws.com/?fresh=1"}, nil
					},
				}
			},
			wantURL:     "https://sts.amazonaws.com/?fresh=1",
			checkCached: true,
		},
		{
			name:    "stale cache presigns again",
			profile: "static-profile",
			setupFn: func() {
				keyring.Set(keyringService, "static-profile", string(staticJSON)) //nolint:errcheck,gosec // ok

				cache := stsURLCache{URL: "https://sts.amazonaws.com/?cached=1", IssuedAt: time.Now().Add(-stsURLAssumedTTL)}
				b, _ := json.Marshal(cache)                                    //nolint:errcheck // ok
				keyring.Set(stsURLKeyringService, "static-profile", string(b)) //nolint:errcheck,gosec // ok
			},
			presign: func(t *testing.T) *mockPresignClient {
				t.Helper()

				return &mockPresignClient{
					presignFunc: func(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
						return &v4.PresignedHTTPRequest{URL: "https://sts.amazonaws.com/?refreshed=1"}, nil
					},
				}
			},
			wantURL: "https://sts.amazonaws.com/?refreshed=1",
		},
		{
			name:    "credential resolution failure",
			profile: "nonexistent",
			setupFn: func() {},
			presign: freshMock,
			wantErr: true,
		},
		{
			name:    "presign failure",
			profile: "static-profile",
			setupFn: func() {
				keyring.Set(keyringService, "static-profile", string(staticJSON)) //nolint:errcheck,gosec // ok
			},
			presign: func(t *testing.T) *mockPresignClient {
				t.Helper()

				return &mockPresignClient{
					presignFunc: func(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
						return nil, errors.New("access denied")
					},
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring.MockInit()
			tt.setupFn()

			a := app{
				SkewPad:    120 * time.Second,
				SessionTTL: 3600 * time.Second,
				AWSProfile: tt.profile,
				mkPresignClient: func(aws.CredentialsProvider) stsPresignAPI {
					return tt.presign(t)
				},
			}

			got, err := a.resolveSTSURL(t.Context())
			if (err != nil) != tt.wantErr {
				t.Fatalf("resolveSTSURL() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if got != tt.wantURL {
				t.Errorf("resolveSTSURL() = %q, want %q", got, tt.wantURL)
			}

			if tt.checkCached {
				var cache stsURLCache

				if err = cache.load(tt.profile); err != nil {
					t.Fatalf("expected cache to be stored: %v", err)
				}

				if cache.URL != tt.wantURL {
					t.Errorf("cached URL = %q, want %q", cache.URL, tt.wantURL)
				}
			}
		})
	}
}
