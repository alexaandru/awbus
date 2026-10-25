package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestGenericKeyAndGetPut(t *testing.T) {
	keyring.MockInit()

	if got := genericKey("openai", "me@x.com"); got != "openai/me@x.com" {
		t.Fatalf("genericKey = %q", got)
	}

	if err := keyring.Set("openai", "me@x.com", "legacy-secret"); err != nil {
		t.Fatal(err)
	}

	got, err := getGeneric("openai", "me@x.com")
	if err != nil || got != "legacy-secret" {
		t.Fatalf("legacy get: %q %v", got, err)
	}

	if err = putGeneric("openai", "me@x.com", "new-secret"); err != nil {
		t.Fatal(err)
	}

	got, err = keyring.Get(genericKeyringService, "openai/me@x.com")
	if err != nil || got != "new-secret" {
		t.Fatalf("new store: %q %v", got, err)
	}

	if _, err = keyring.Get("openai", "me@x.com"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("legacy should be deleted, err=%v", err)
	}

	got, err = getGeneric("openai", "me@x.com")
	if err != nil || got != "new-secret" {
		t.Fatalf("get after put: %q %v", got, err)
	}
}

func TestParseAwbusGets(t *testing.T) {
	src := `
# comment
export X=$(awbus get openai me@x.com)
GITLAB_TOKEN="$(${GOPATH}/bin/awbus get alpine-gitlab alex@y.com)" command glab
awbus get ssh $i | ssh-add -
/usr/bin/awbus get claude 'aungur@prognoshealth.com'
`
	refs, skipped := parseAwbusGets("cfg.sh", []byte(src))

	if len(skipped) != 0 {
		t.Fatalf("skipped=%v, want none", skipped)
	}

	if len(refs) != 4 {
		t.Fatalf("refs=%d %+v, want 4", len(refs), refs)
	}

	var sawSSHAll bool

	for _, r := range refs {
		if r.Kind == "ssh" && r.All {
			sawSSHAll = true
		}
	}

	if !sawSSHAll {
		t.Fatalf("expected ssh All ref, got %+v", refs)
	}
}

func TestMigrateGenericPairAndDiscover(t *testing.T) {
	keyring.MockInit()
	isolateMigrateRoots(t)

	if err := keyring.Set("claude", "a@b.com", "tok"); err != nil {
		t.Fatal(err)
	}

	if err := migrateGenericPair("claude", "a@b.com"); err != nil {
		t.Fatal(err)
	}

	got, err := keyring.Get(genericKeyringService, "claude/a@b.com")
	if err != nil || got != "tok" {
		t.Fatalf("migrated=%q err=%v", got, err)
	}

	if err = keyring.Set("ssh", "alexaandru", "k1"); err != nil {
		t.Fatal(err)
	}

	if err = keyring.Set("ssh", "husky", "k2"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfg := filepath.Join(dir, "rc")

	if err = os.WriteFile(cfg, []byte("awbus get claude a@b.com\nawbus get ssh $i\nawbus get $KIND x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	refs, skipped, files, err := discoverGenericRefs([]string{cfg})
	if err != nil {
		t.Fatal(err)
	}

	if len(files) != 1 {
		t.Fatalf("files=%v", files)
	}

	if len(skipped) != 1 || !strings.Contains(skipped[0], "dynamic kind") {
		t.Fatalf("skipped=%v", skipped)
	}

	// claude/a@b.com already migrated above + ssh/alexaandru + ssh/husky from $i.
	if len(refs) != 3 {
		t.Fatalf("refs=%+v, want 3", refs)
	}
}

func isolateMigrateRoots(t *testing.T) {
	t.Helper()

	empty := t.TempDir()
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv("ZDOTDIR", empty)
	t.Setenv("HOME", empty)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(empty, ".config"))
}

func TestListUsersSorted(t *testing.T) {
	keyring.MockInit()

	if err := keyring.Set(genericKeyringService, "b/x", "1"); err != nil {
		t.Fatal(err)
	}

	if err := keyring.Set(genericKeyringService, "a/y", "2"); err != nil {
		t.Fatal(err)
	}

	users, err := listUsers(genericKeyringService)
	if err != nil {
		t.Fatal(err)
	}

	if len(users) != 2 || users[0] != "a/y" || users[1] != "b/x" {
		t.Fatalf("users=%v", users)
	}
}

func TestMigrateFromConfigsConfirm(t *testing.T) {
	keyring.MockInit()
	isolateMigrateRoots(t)

	if err := keyring.Set("openai", "me@x.com", "s3cret"); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	cfg := filepath.Join(dir, "rc")

	if err := os.WriteFile(cfg, []byte("awbus get openai me@x.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	a := app{prompt: func(_ string, val *string) error {
		*val = "y"

		return nil
	}}

	if err := a.migrateFromConfigs([]string{cfg}); err != nil {
		t.Fatal(err)
	}

	got, err := getGeneric("openai", "me@x.com")
	if err != nil || got != "s3cret" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestListAllAndEmptySection(t *testing.T) {
	keyring.MockInit()

	if err := keyring.Set(keyringService, "p1", "{}"); err != nil {
		t.Fatal(err)
	}

	a := app{}
	if err := a.listAll(); err != nil {
		t.Fatal(err)
	}

	if err := printListSection("empty", "no-such-service-zzzz"); err != nil {
		t.Fatal(err)
	}
}

func TestPrintListNamesPlain(t *testing.T) {
	keyring.MockInit()

	if err := keyring.Set(otpKeyringService, "Slack", "{}"); err != nil {
		t.Fatal(err)
	}

	if err := keyring.Set(otpKeyringService, "NPM", "{}"); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout

	t.Cleanup(func() { os.Stdout = oldStdout })

	os.Stdout = w

	if err = printListNames(otpKeyringService); err != nil {
		t.Fatal(err)
	}

	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	got := string(raw)
	if got != "NPM\nSlack\n" {
		t.Fatalf("got %q", got)
	}

	if err = printListNames("no-such-service-zzzz"); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateGenericPairAlreadyMigratedAndMissing(t *testing.T) {
	keyring.MockInit()

	if err := putGeneric("k", "n", "v"); err != nil {
		t.Fatal(err)
	}

	// Already in awbus-generic; leftover legacy should be cleaned.
	if err := keyring.Set("k", "n", "old"); err != nil {
		t.Fatal(err)
	}

	if err := migrateGenericPair("k", "n"); err != nil {
		t.Fatal(err)
	}

	if _, err := keyring.Get("k", "n"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("legacy leftover err=%v", err)
	}

	err := migrateGenericPair("missing-kind", "missing-name")
	if err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("want legacy miss error, got %v", err)
	}
}

func TestMigrateFromConfigsAbortAndMissingAndNothing(t *testing.T) {
	keyring.MockInit()
	isolateMigrateRoots(t)

	dir := t.TempDir()
	cfg := filepath.Join(dir, "rc")

	if err := os.WriteFile(cfg, []byte("awbus get openai gone@x.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cli := app{prompt: func(_ string, val *string) error {
		*val = "n"

		return nil
	}}
	if err := cli.migrateFromConfigs([]string{cfg}); err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("want abort, got %v", err)
	}

	cli.prompt = func(_ string, val *string) error {
		*val = "yes"

		return nil
	}
	if err := cli.migrateFromConfigs([]string{cfg}); err != nil {
		t.Fatal(err)
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("# no gets\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cli.migrateFromConfigs([]string{empty}); err != nil {
		t.Fatal(err)
	}

	cli.prompt = func(string, *string) error { return errors.New("EOF") }

	if err := os.WriteFile(cfg, []byte("awbus get openai still@x.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cli.migrateFromConfigs([]string{cfg}); err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("want abort on empty prompt, got %v", err)
	}
}

func TestDefaultMigrateRootsAndCollectDir(t *testing.T) { //nolint:funlen // ok
	empty := t.TempDir()

	t.Run("zsh", func(t *testing.T) {
		t.Setenv("SHELL", "/bin/zsh")
		t.Setenv("ZDOTDIR", empty)
		t.Setenv("HOME", empty)

		roots := defaultMigrateRoots()
		if len(roots) != 4 || !strings.HasSuffix(roots[0], ".zshrc") {
			t.Fatalf("zsh roots=%v", roots)
		}
	})

	t.Run("bash", func(t *testing.T) {
		t.Setenv("SHELL", "/bin/bash")
		t.Setenv("HOME", empty)
		t.Setenv("BASH_ENV", filepath.Join(empty, "bashenv"))

		roots := defaultMigrateRoots()
		if len(roots) < 4 {
			t.Fatalf("bash roots=%v", roots)
		}
	})

	t.Run("fish", func(t *testing.T) {
		t.Setenv("SHELL", "/usr/bin/fish")
		t.Setenv("HOME", empty)
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(empty, ".config"))

		roots := defaultMigrateRoots()
		if len(roots) != 1 || !strings.Contains(roots[0], "config.fish") {
			t.Fatalf("fish roots=%v", roots)
		}
	})

	t.Run("other", func(t *testing.T) {
		t.Setenv("SHELL", "/bin/osh")
		t.Setenv("HOME", empty)

		roots := defaultMigrateRoots()
		if len(roots) != 3 {
			t.Fatalf("other roots=%v", roots)
		}
	})

	t.Run("collect dir walk", func(t *testing.T) {
		t.Setenv("SHELL", "/bin/zsh")
		t.Setenv("ZDOTDIR", empty)
		t.Setenv("HOME", empty)

		root := t.TempDir()
		sub := filepath.Join(root, "sub")

		if err := os.MkdirAll(filepath.Join(sub, ".git"), 0o700); err != nil {
			t.Fatal(err)
		}

		cfg := filepath.Join(sub, "rc.sh")
		if err := os.WriteFile(cfg, []byte("awbus get a b\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(sub, "x.db"), []byte("nope"), 0o600); err != nil {
			t.Fatal(err)
		}

		files, err := collectMigrateFiles([]string{root})
		if err != nil {
			t.Fatal(err)
		}

		if len(files) != 1 || files[0] != cfg {
			t.Fatalf("files=%v", files)
		}
	})
}

func TestStripTokenAndCmpOrEnvAndExpandEmpty(t *testing.T) {
	keyring.MockInit()

	if got := stripToken(`"quoted"`); got != "quoted" {
		t.Fatalf("quoted=%q", got)
	}

	if got := stripToken(`'x')`); got != "x" {
		t.Fatalf("trimmed=%q", got)
	}

	t.Setenv("AWBUS_TEST_CMP", "set")

	if got := cmpOrEnv("AWBUS_TEST_CMP", "fallback"); got != "set" {
		t.Fatalf("cmp set=%q", got)
	}

	if got := cmpOrEnv("AWBUS_TEST_CMP_MISSING", "fallback"); got != "fallback" {
		t.Fatalf("cmp fallback=%q", got)
	}

	out, err := expandDynamicRefs([]genericRef{{Kind: "empty-svc", Name: "*", All: true, Src: "t:1"}})
	if err != nil {
		t.Fatal(err)
	}

	if len(out) != 0 {
		t.Fatalf("out=%v", out)
	}
}

func TestParseAwbusGetsEmptyTokens(t *testing.T) {
	refs, skipped := parseAwbusGets("x", []byte("awbus get   \n"))
	if len(refs) != 0 {
		t.Fatalf("refs=%v", refs)
	}

	// Second capture may be empty depending on regex; ensure no panic.
	_ = skipped
}
