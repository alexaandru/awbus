package main

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zalando/go-keyring"
)

// stsURLCache is a cached presigned STS GetCallerIdentity URL, keyed by
// profile in its own keyring service so it never collides with Creds.
type stsURLCache struct {
	IssuedAt time.Time `json:"IssuedAt"`
	URL      string    `json:"Url"`
}

// resolveSTSURL returns a presigned STS GetCallerIdentity URL for the current
// profile's resolved credentials, suitable for an `Authorization: IAM <url>`
// header. Reuses a cached URL until it's within SkewPad of stsURLAssumedTTL,
// refreshing (and re-resolving credentials, if those themselves need it) only
// when necessary - this is what makes it safe to call on every request.
func (a *app) resolveSTSURL(ctx context.Context) (string, error) {
	var cache stsURLCache

	now := time.Now()
	if err := cache.load(a.AWSProfile); err == nil && cache.fresh(now, a.SkewPad) {
		return cache.URL, nil
	}

	c, err := a.resolveAndMaybeRefresh(ctx, a.AWSProfile)
	if err != nil {
		return "", fmt.Errorf("resolve credentials for profile %q: %w", a.AWSProfile, err)
	}

	presigned, err := a.mkPresignClient(credsProvider(c)).PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("presign GetCallerIdentity: %w", err)
	}

	cache = stsURLCache{URL: presigned.URL, IssuedAt: now}
	if err = cache.store(a.AWSProfile); err != nil {
		return "", fmt.Errorf("persist presigned URL cache: %w", err)
	}

	return cache.URL, nil
}

func (c *stsURLCache) load(profile string) (err error) {
	raw, err := keyring.Get(stsURLKeyringService, profile)
	if err != nil {
		return err
	}

	return json.Unmarshal([]byte(raw), c)
}

func (c *stsURLCache) store(profile string) (err error) {
	b, err := json.Marshal(*c)
	if err != nil {
		return err
	}

	return keyring.Set(stsURLKeyringService, profile, string(b))
}

func (c *stsURLCache) fresh(now time.Time, skewPad time.Duration) bool {
	return c.URL != "" && now.Add(skewPad).Before(c.IssuedAt.Add(stsURLAssumedTTL))
}
