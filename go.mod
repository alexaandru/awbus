module github.com/alexaandru/awbus

go 1.27.3

// Creds.load fails on any profile with a text-form SessionTTL/SkewPad (e.g. "1h0m0s", the format every profile written before this used).
retract v1.3.0

require (
	github.com/alexaandru/confetti v1.6.3
	github.com/aws/aws-sdk-go-v2 v1.47.8
	github.com/aws/aws-sdk-go-v2/config v1.33.16
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.75.10
	github.com/aws/aws-sdk-go-v2/service/iam v1.64.9
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.9
	github.com/pquerna/otp v1.5.0
	github.com/zalando/go-keyring v0.2.9-0.20260724212736-66b55cc0c51c
	golang.org/x/term v0.47.0
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.20.16 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.8 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.12.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssm v1.82.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.39.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.44.4 // indirect
	github.com/aws/smithy-go v1.28.8 // indirect
	github.com/boombuler/barcode v1.1.0 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/godbus/dbus/v5 v5.2.4 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
