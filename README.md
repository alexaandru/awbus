# awbus - AWS to Secret Service bridge

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Test](https://github.com/alexaandru/awbus/actions/workflows/ci.yml/badge.svg)](https://github.com/alexaandru/awbus/actions/workflows/ci.yml)
![Coverage](coverage-badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexaandru/awbus?nocache=1)](https://goreportcard.com/report/github.com/alexaandru/awbus?nocache=1)
[![Go Reference](https://pkg.go.dev/badge/github.com/alexaandru/awbus.svg)](https://pkg.go.dev/github.com/alexaandru/awbus)
[![Socket.dev](https://socket.dev/api/badge/go/package/github.com/alexaandru/awbus)](https://socket.dev/go/package/github.com/alexaandru/awbus)

AWS [credential_process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)
helper using system keyring with secure storage, automatic credential management, and generic keyring operations.

## 📋 Overview

`awbus` securely stores AWS credentials in your system keyring (GNOME Keyring, macOS Keychain, Windows Credential Manager) and provides them via the AWS `credential_process` interface. Features:

- **Cross-platform keyring support** - Works on Linux, macOS, and Windows
- **Multiple credential types** - Static credentials and assumed roles with automatic refresh
- **Smart caching** - Automatically refreshes session credentials before expiration
- **Zero configuration** - Works seamlessly with existing AWS CLI profiles
  (i.e. aws cli, terraform apply, code that uses AWS SDK should all work unmodified)
- **Profile management** - Store, delete, and manage multiple AWS profiles
- **Generic keyring operations** - Store and retrieve arbitrary secrets securely

## 📦 Installation

```bash
go install github.com/alexaandru/awbus@latest
```

## 🚩 Flags

- `-profile <name>` - Override profile name (takes precedence over `AWS_PROFILE`)

## 🌍 Environment Variables

awbus operation is controlled by these environment variables:

- `AWS_PROFILE` - Profile name (default: "default")
- `AWS_REGION` - AWS region for STS operations (default: "us-east-1")
- `SKEW_PAD` - Refresh window before expiration (default: "120s")
- `SESSION_TTL` - AssumeRole session duration (default: "1h")

## 🚀 Usage

1. Store credentials: `awbus store` or `awbus store-assume`
2. Optionally, verify that they are loaded (i.e. for Linux: `secret-tool search --all service awbus`)
3. Configure AWS profile in `~/.aws/credentials` and replace hardcoded credentials with:
   ```toml
   [myprofile]
   credential_process = /path/to/awbus
   ```
4. Use AWS CLI/SDK (incl. Terraform, anything that knows how to use AWS profiles) normally - `awbus` handles credential retrieval

## ⚡ Commands

| Command          | Description                                                   |
| ---------------- | ------------------------------------------------------------- |
| `load` (default) | 🔐 Load+display credentials for current (AWS_PROFILE) profile |
| `store`          | 💾 Store static AWS credentials (interactive)                 |
| `store-assume`   | 🎭 Store assumed role configuration (interactive)             |
| `rotate`         | 🔄 Rotate static credentials (create new, delete old)         |
| `delete`         | 🗑️ Delete profile from keyring (interactive)                  |
| `get`            | 🔍 Get arbitrary secret: `awbus get <service> <username>`     |
| `put`            | 💾 Store arbitrary secret: `awbus put [service] [username]`   |
| `version`        | ℹ️ Show version                                               |
| `help`           | ❓ Show detailed help                                         |

## 🔐 Generic Keyring Operations

Beyond AWS credentials, `awbus` can store and retrieve arbitrary secrets:

```bash
# Store a secret (prompts for secret securely)
awbus put myapp myuser

# Store a secret with stdin (secure - no command line exposure)
get_my_secret.sh | awbus put myapp myuser

# Retrieve a secret
awbus get myapp myuser

# Interactive mode (prompts for all missing values)
awbus put
```

**Security Note**: Secrets are never accepted as command line arguments to prevent exposure in shell history or process lists.
Use stdin piping (**NOT echo**, that will leave the secret in history) or interactive prompts only.

## 📄 License

[MIT](LICENSE)
