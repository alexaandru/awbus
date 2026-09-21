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
  - presigned STS `GetCallerIdentity` URLs, cached and auto-refreshed, for services
    authenticating via AWS IAM identity (`Authorization: IAM <url>`)
  - Cognito User Pool JWTs, cached and auto-refreshed, for a user signed in with
    a username and password
  - generic keyring operations: store and retrieve arbitrary secrets securely
- **Smart caching** - Automatically refreshes AWS session credentials before expiration
- **Zero configuration** - Works seamlessly with existing AWS CLI profiles
  (i.e. `aws cli`, `terraform apply`, code that uses **AWS SDK**, etc. should all work unmodified)
- **Cross-platform keyring support** - Works on **Linux**, **MacOS**, and **Windows**

## 📦 Installation

```bash
go install github.com/alexaandru/awbus@latest
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

- `-profile <name>` - Override profile name (takes precedence over `AWS_PROFILE`). Used by
  `load`/`store`/`store-assume`/`rotate`/`delete`/`sts-url` only.
- `-pool <name>` - Which Cognito pool config to use (default: `"default"`). Used by
  `jwt`/`jwt-add-user`/`jwt-set-default-user` only, entirely independent of `-profile`/`AWS_PROFILE` -
  Cognito needs no AWS credentials, so a pool's config and users aren't tied to any AWS profile.
- `-user <sel>`, `-token <kind>` - see the Cognito JWTs section below.

Commands:

| Command                | Description                                                                    |
| ---------------------- | ------------------------------------------------------------------------------ |
| `load` (default)       | 🔐 Load+display credentials for current (AWS_PROFILE) profile                  |
| `store`                | 💾 Store static AWS credentials (interactive)                                  |
| `store-assume`         | 🎭 Store assumed role configuration (interactive)                              |
| `rotate`               | 🔄 Rotate static credentials (create new, delete old)                          |
| `delete`               | 🗑️ Delete profile from keyring (interactive)                                   |
| `sts-url`              | 🔏 Cached, auto-refreshed presigned STS `GetCallerIdentity` URL                |
| `jwt`                  | 🪪 Cached, auto-refreshed Cognito User Pool JWT (auto-provisions on first use) |
| `jwt-add-user`         | ➕ Register an additional existing Cognito user with the pool (interactive)    |
| `jwt-set-default-user` | 🎯 Set the pool's default Cognito user                                         |
| `get`                  | 🔍 Get arbitrary secret: `awbus get <service> <username>`                      |
| `put`                  | 💾 Store arbitrary secret: `awbus put [service] [username]`                    |
| `version`              | ℹ️ Show version                                                                |
| `help`                 | ❓ Show detailed help                                                          |

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

### Presigned STS URLs (IAM auth)

For services that authenticate callers via AWS IAM identity rather than a static API key
(presigned `sts:GetCallerIdentity`, e.g. `Authorization: IAM <url>`), `sts-url` hands you one
ready to use - cached and refreshed automatically, so it's safe to call on every request:

```bash
curl -H "Authorization: IAM $(awbus -profile myprofile sts-url)" https://api.your-service.com/
```

### Cognito User Pool JWTs

`jwt` signs a user in to a named Cognito pool (`-pool`, default `"default"` - independent of any
AWS profile, since Cognito needs no AWS credentials at all) and hands the resulting JWT - cached
and refreshed automatically (via the stored refresh token, falling back to a full password
re-auth once that's expired), so it's safe to call on every request. The pool's app client just
needs `ALLOW_USER_PASSWORD_AUTH`/`ALLOW_REFRESH_TOKEN_AUTH` enabled. The first call on a pool
prompts to configure it and its first user; `awbus` never creates or modifies users in Cognito
itself, it only stores an existing user's credentials locally:

```bash
curl -H "Authorization: Bearer $(awbus jwt)" https://api.your-service.com/
```

A pool can hold multiple Cognito users - `-user <prefix>` picks one by an unambiguous prefix of
its username, `-user -` prompts for one interactively, and `jwt-add-user` / `jwt-set-default-user`
manage the set and its default explicitly:

```bash
awbus jwt -user alice          # unambiguous prefix
awbus jwt-add-user             # register another existing user
awbus jwt-set-default-user -user bob
```

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

### Secrets for Other Tools

Plenty of tools only take their credentials from a config file or an environment
variable. You can feed them from the keyring instead, so the secret exists only
while the tool is actually running.

First, store the secret (one time operation):

```bash
awbus put openrouter you@example.com # will prompt, never pass a secret in commandline
```

#### Best: let the tool fetch it itself

Some tools accept a *command* to run for the credential rather than a literal
value. Then no environment variable is ever created, and the secret never touches
the config file. The [pi](https://pi.dev) coding agent does this with a `!`
prefix - put this in its `models.json`:

```json
{
  "providers": {
    "openrouter": {
      "apiKey": "!awbus get openrouter you@example.com"
    }
  }
}
```

This is the same shape as AWS's `credential_process`, which `awbus load`
implements.

#### Otherwise: a per-command wrapper

If the tool insists on an environment variable, wrap it in a shell function that
sets the variable for that one invocation only:

```bash
# in ~/.bashrc, ~/.zshrc, etc.
claude() {
  CLAUDE_CODE_OAUTH_TOKEN="$(awbus get claude you@example.com)" command claude "$@"
}
```

The `command` prefix is required: the function shadows the real binary, so without
it you get infinite recursion.

#### Why not just export it

```bash
# in ~/.zshenv:
export CLAUDE_CODE_OAUTH_TOKEN="$(awbus get claude you@example.com)"
```

This also keeps the secret out of your dotfiles, but the variable then lands in
the environment of *every* process you spawn for the rest of the session, not just
the one that needs it: it shows up in `env` output, in `/proc/<pid>/environ` for
anything running as you, and in whatever your tools dump on a crash. It's also
read once at login, so it goes stale the moment you rotate the secret.

The wrapper doesn't make the variable invisible - it's still in that child
process's environment while it runs, and still readable from `/proc` by anything
running as you. What it changes is the blast radius: one process instead of all of
them, for seconds instead of for the whole session, and always the current value of
the secret.

## 📄 License

[MIT](LICENSE)
