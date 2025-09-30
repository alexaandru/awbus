# awbus - AWS to Secret Service bridge

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Test](https://github.com/alexaandru/awbus/actions/workflows/ci.yml/badge.svg)](https://github.com/alexaandru/awbus/actions/workflows/ci.yml)
![Coverage](coverage-badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexaandru/awbus)](https://goreportcard.com/report/github.com/alexaandru/awbus)
[![Go Reference](https://pkg.go.dev/badge/github.com/alexaandru/awbus.svg)](https://pkg.go.dev/github.com/alexaandru/awbus)
[![Socket.dev](https://socket.dev/api/badge/go/package/github.com/alexaandru/awbus)](https://socket.dev/go/package/github.com/alexaandru/awbus)

AWS credential_process helper using system keyring with secure storage and automatic credential management.

## 📋 Overview

`awbus` securely stores AWS credentials in your system keyring (GNOME Keyring, macOS Keychain, Windows Credential Manager) and provides them via the AWS `credential_process` interface. Features:

- **Cross-platform keyring support** - Works on Linux, macOS, and Windows
- **Multiple credential types** - Static credentials and assumed roles with automatic refresh
- **Smart caching** - Automatically refreshes session credentials before expiration
- **Zero configuration** - Works seamlessly with existing AWS CLI profiles
- **Profile management** - Store, delete, and manage multiple AWS profiles
- **Security-first** - No credentials stored in plain text or process environment

## 📦 Installation

```bash
go install github.com/alexaandru/awbus@latest
```

## 🌍 Environment Variables

awbus operation is controlled by these environment variables:

- `AWS_PROFILE` - Profile name (default: "default")
- `AWS_REGION` - AWS region for STS operations (default: "us-east-1")
- `SKEW_PAD` - Refresh window before expiration (default: "120s")
- `SESSION_TTL` - AssumeRole session duration (default: "1h")

## 🚀 Usage

1. Store credentials: `awbus store` or `awbus store-assume`
1. Optionally, verify that they are loaded (i.e. for Linux: `secret-tool search --all service awbus`);
1. Configure AWS profile in `~/.aws/credentials` and replace harcoded credentials with:
   ```toml
   [myprofile]
   credential_process = /path/to/awbus
   ```
1. Use AWS CLI/SDK (incl. Terraform, anything that knows how to use AWS profiles) normally - `awbus` handles credential retrieval.

## ⚡ Commands

| Command          | Description                                                   |
| ---------------- | ------------------------------------------------------------- |
| `load` (default) | 🔐 Load+display credentials for current (AWS_PROFILE) profile |
| `store`          | 💾 Store static AWS credentials (interactive)                 |
| `store-assume`   | 🎭 Store assumed role configuration (interactive)             |
| `rotate`         | 🔄 Rotate static credentials (create new, delete old)         |
| `delete`         | 🗑️ Delete profile from keyring (interactive)                  |
| `version`        | ℹ️ Show version                                               |
| `help`           | ❓ Show detailed help                                         |

## 📋 Requirements

System keyring support: Linux (Secret Service/D-Bus), macOS (Keychain), Windows (Credential Manager)

## 📄 License

[MIT](LICENSE)
