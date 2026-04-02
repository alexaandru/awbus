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

`awbus` securely stores AWS credentials in your system keyring (**GNOME Keyring**, **MacOS Keychain**, **Windows Credential Manager**)
and provides them via the AWS `credential_process` interface. Features:

- **Multiple credential types**:
  - static AWS credentials (for a profile)
  - assumed AWS roles (with automatic refresh)
  - generic keyring operations: store and retrieve arbitrary secrets securely
- **Smart caching** - Automatically refreshes AWS session credentials before expiration
- **Zero configuration** - Works seamlessly with existing AWS CLI profiles
  (i.e. `aws cli`, `terraform apply`, code that uses **AWS SDK**, etc. should all work unmodified)
- **Cross-platform keyring support** - Works on **Linux**, **MacOS**, and **Windows**

## 📦 Installation

```bash
GOEXPERIMENT=jsonv2 go install github.com/alexaandru/awbus@latest
```

That will place the binary under `$(go env GOPATH)/bin` folder. You can either
add that folder to your `$PATH` or use the full path (i.e. the output of
`$(which awbus)` when referencing the binary).

## 📖 Usage

`awbus` operation is controlled by these environment variables:

- `AWS_PROFILE` - Profile name (default: "default")
- `AWS_REGION` - AWS region for STS operations (default: "us-east-1")
- `SKEW_PAD` - Refresh window before expiration (default: "120s")
- `SESSION_TTL` - AssumeRole session duration (default: "1h")

and these flags:

- `-profile <name>` - Override profile name (takes precedence over `AWS_PROFILE`)

Commands:

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

The `store[-assume]`/`load` pairs work on **AWS profiles** while `put`/`get` work on **generic** (arbitrary)
**secrets**:

```bash
awbus put myapp myuser # Store a secret (prompts for secret securely)
awbus put              # OR prompt for all missing values: app/service, user and secret
cat secret.txt | awbus put myapp myuser # OR pass secret to stdin

awbus get myapp myuser # Retrieve the secret
```

**Security Note**: Secrets are never accepted as command line arguments to prevent exposure in shell history or process lists.
Use stdin piping (**NOT echo**, that will leave the secret in history) or interactive prompts only.

## 🚀 Use Cases

### AWS Credentials

1. Store credentials: `awbus store` or `awbus store-assume`
2. Optionally, verify that they are loaded (i.e. for Linux: `secret-tool search --all service awbus`)
3. Configure AWS profile in `~/.aws/credentials` and replace hardcoded credentials with:

   ```toml
   [profile1]
   credential_process = awbus -profile profile1

   [profile2]
   credential_process = awbus -profile profile2
   region = us-east-2

   ...
   ```

4. Use AWS CLI/SDK (incl. Terraform, anything that knows how to use AWS profiles) normally - `awbus` handles credential retrieval

### SSH Keys

Store private keys in the keyring and load them straight into `ssh-agent` on demand — no
keys sitting unencrypted on disk:

```bash
# Store a private key
cat ~/.ssh/id_ed25519| awbus put ssh id_ed25519

# Launch ssh-agent and add the key from the keyring
eval $(ssh-agent)
awbus get ssh id_ed25519| ssh-add -
```

See ssh-agent tutorials/docs for how to set it up, but as a rule of thumb, you
want it started (and loaded) at login time, so that it is available for all your
terminals. The example above would only work on the terminal where the eval was
run, but other terminals would not have access to the same ssh agent.

> **Note**: Don't forget to delete the keys on disk after you confirm they
> load correctly from the keyring.

### Shell Environment Variables

Export secrets as environment variables without hardcoding them in dotfiles:

```bash
# 1st, store them (one time operation):
awbus put myapp apikey # will prompt for secret, never pass it in commandline
awbus put mydb url     # same

# Then, in ~/.bashrc, ~/.zshenv, etc.
export MY_API_KEY="$(awbus get myapp apikey)"
export DATABASE_URL="$(awbus get mydb url)"
```

This way, secrets stay in the keyring & dotfiles stay secrets free.

## 📄 License

[MIT](LICENSE)
