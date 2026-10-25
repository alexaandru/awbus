package main

import (
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

func testOTPSecret() string {
	// Standard base32 test vector ("Hello!"), not a real credential.
	return "JBSWY3DPEHPK3PXP"
}

func TestOTPStoreLoadCodeVerify(t *testing.T) {
	keyring.MockInit()

	origClip := clipboardWrite

	t.Cleanup(func() { clipboardWrite = origClip })

	var clipped string

	clipboardWrite = func(s string) error {
		clipped = s

		return nil
	}

	e := otpEntry{
		Username:  "Test",
		Secret:    testOTPSecret(),
		Issuer:    "Test",
		Period:    "30",
		Algorithm: "sha1",
		Digits:    "6",
	}
	if err := e.store(); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadOTP("Test")
	if err != nil {
		t.Fatal(err)
	}

	if loaded.Secret != e.Secret {
		t.Fatalf("secret=%q", loaded.Secret)
	}

	a := app{}
	if err = a.otpCode("Test"); err != nil {
		t.Fatal(err)
	}

	if clipped == "" {
		t.Fatal("expected clipboard write")
	}

	opts, err := loaded.validateOpts()
	if err != nil {
		t.Fatal(err)
	}

	ok, err := totp.ValidateCustom(clipped, loaded.Secret, time.Now().UTC(), opts)
	if err != nil || !ok {
		t.Fatalf("validate clipped code: ok=%v err=%v", ok, err)
	}

	if err = a.otpVerify("Test", clipped); err != nil {
		t.Fatal(err)
	}
}

func TestOTPImportExportRoundTrip(t *testing.T) {
	keyring.MockInit()

	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	out := filepath.Join(dir, "out.json")
	sec := testOTPSecret()
	src := []otpFileEntry{
		{Username: "PayPal", Secret: sec, Issuer: "PayPal", Period: "30", Algorithm: "sha1", Digits: "6"},
		{Username: "AWS/Prognos", Secret: sec, Issuer: "AWS", Period: "30", Algorithm: "sha1", Digits: "6"},
	}

	b, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}

	if err = os.WriteFile(in, b, 0o600); err != nil {
		t.Fatal(err)
	}

	cli := app{prompt: func(string, *string) error {
		t.Fatal("prompt should not run for new imports")

		return nil
	}}
	if err = cli.otpImport(in); err != nil {
		t.Fatal(err)
	}

	names, err := listUsers(otpKeyringService)
	if err != nil || len(names) != 2 {
		t.Fatalf("names=%v err=%v", names, err)
	}

	if err = cli.otpExport(out); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(out) //nolint:gosec // ok
	if err != nil {
		t.Fatal(err)
	}

	var got []otpFileEntry
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 {
		t.Fatalf("exported=%d", len(got))
	}

	cli.prompt = func(_ string, val *string) error {
		*val = "n"

		return nil
	}
	if err = cli.otpImport(in); err != nil {
		t.Fatal(err)
	}
}

func TestOTPAddAndDelete(t *testing.T) {
	keyring.MockInit()

	a := app{prompt: func(label string, val *string) error {
		switch {
		case label == "Username":
			*val = "Slack"
		case label == "Secret":
			*val = testOTPSecret()
		case strings.HasPrefix(label, "Delete otp"):
			*val = "y"
		default:
			return errors.New("EOF") // optional fields → defaults
		}

		return nil
	}}

	if err := a.otpAdd("", otpAddOpts{}); err != nil {
		t.Fatal(err)
	}

	if _, err := loadOTP("Slack"); err != nil {
		t.Fatal(err)
	}

	if err := a.otpDelete("Slack"); err != nil {
		t.Fatal(err)
	}

	if _, err := loadOTP("Slack"); !errors.Is(err, keyring.ErrNotFound) && !strings.Contains(err.Error(), "secret not found") {
		// loadOTP wraps ErrNotFound
		if err == nil {
			t.Fatal("expected missing after delete")
		}
	}
}

func TestOTPCommandDispatchAndList(t *testing.T) {
	keyring.MockInit()

	e := otpEntry{Username: "NPM", Secret: testOTPSecret()}
	if err := e.store(); err != nil {
		t.Fatal(err)
	}

	clipboardWrite = func(string) error { return nil }

	a := app{}
	if err := a.otpCommand([]string{"list"}, otpAddOpts{}); err != nil {
		t.Fatal(err)
	}

	if err := a.otpCommand([]string{"nope"}, otpAddOpts{}); err == nil {
		t.Fatal("want unknown subcommand error")
	}

	if err := a.run(t.Context(), []string{"awbus", "list-otp"}); err != nil {
		t.Fatal(err)
	}

	if err := a.run(t.Context(), []string{"awbus", "otp", "code", "NPM"}); err != nil {
		t.Fatal(err)
	}
}

func TestOTPValidateOptsErrors(t *testing.T) {
	e := otpEntry{Username: "x", Secret: "y", Period: "nope"}
	if err := e.validate(); err == nil {
		t.Fatal("want period error")
	}

	e = otpEntry{Username: "x", Secret: "y", Digits: "7"}
	if err := e.validate(); err == nil {
		t.Fatal("want digits error")
	}

	e = otpEntry{Username: "x", Secret: "y", Algorithm: "md5"}
	if err := e.validate(); err == nil {
		t.Fatal("want algorithm error")
	}

	e = otpEntry{Secret: "y"}
	if err := e.validate(); err == nil {
		t.Fatal("want username required")
	}

	e = otpEntry{Username: "x"}
	if err := e.validate(); err == nil {
		t.Fatal("want secret required")
	}
}

func TestOTPDigitsAndAlgorithms(t *testing.T) {
	if _, err := otpDigits(otpDigitsEight); err != nil {
		t.Fatal(err)
	}

	for _, alg := range []string{"sha256", "sha512", "SHA1"} {
		if _, err := otpAlgorithm(alg); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
	}
}

//nolint:funlen // ok
func TestOTPCommandSubcommands(t *testing.T) {
	keyring.MockInit()

	origClip := clipboardWrite

	t.Cleanup(func() { clipboardWrite = origClip })

	clipboardWrite = func(string) error { return nil }

	sec := testOTPSecret()

	entry := otpEntry{
		Username: "GitHub", Secret: sec, Issuer: "GitHub",
		Period: "30", Algorithm: "sha1", Digits: "6",
	}
	if err := entry.store(); err != nil {
		t.Fatal(err)
	}

	cli := app{prompt: func(label string, val *string) error {
		switch {
		case label == "Username":
			*val = "Extra"
		case label == "Secret":
			*val = sec
		case strings.HasPrefix(label, "Delete otp"):
			*val = "y"
		case strings.Contains(label, "overwrite"):
			*val = "n"
		default:
			return errors.New("EOF")
		}

		return nil
	}}

	code, err := totp.GenerateCodeCustom(sec, time.Now(), totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		args []string
		ok   bool
	}{
		{[]string{}, false},
		{[]string{"code"}, false},
		{[]string{"verify"}, false},
		{[]string{"verify", "GitHub"}, false},
		{[]string{"verify", "GitHub", code}, true},
		{[]string{"delete"}, false},
		{[]string{"import"}, false},
		{[]string{"add", "Extra"}, true},
		{[]string{"delete", "Extra"}, true},
	}

	for _, tc := range cases {
		err = cli.otpCommand(tc.args, otpAddOpts{})
		if tc.ok && err != nil {
			t.Fatalf("args=%v: %v", tc.args, err)
		}

		if !tc.ok && err == nil {
			t.Fatalf("args=%v: want error", tc.args)
		}
	}
}

func TestOTPExportStdoutAndTTYRefuse(t *testing.T) {
	keyring.MockInit()

	entry := otpEntry{Username: "Out", Secret: testOTPSecret()}
	if err := entry.store(); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdout := os.Stdout

	t.Cleanup(func() { os.Stdout = oldStdout })

	os.Stdout = w

	cli := app{}
	if err = cli.otpExport(""); err != nil {
		t.Fatal(err)
	}

	if err = w.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(raw), `"username":"Out"`) {
		t.Fatalf("stdout export=%s", raw)
	}

	os.Stdout = oldStdout
	if term.IsTerminal(int(os.Stdout.Fd())) {
		if err = cli.otpExport(""); err == nil {
			t.Fatal("want TTY refuse")
		}
	}
}

func TestOTPAddOverwriteAbortAndStdinSecret(t *testing.T) {
	keyring.MockInit()

	entry := otpEntry{Username: "Exist", Secret: testOTPSecret()}
	if err := entry.store(); err != nil {
		t.Fatal(err)
	}

	cli := app{prompt: func(label string, val *string) error {
		if strings.Contains(label, "overwrite") {
			*val = "n"

			return nil
		}

		t.Fatalf("unexpected prompt %q", label)

		return nil
	}}
	if err := cli.otpAdd("Exist", otpAddOpts{}); err == nil {
		t.Fatal("want overwrite abort")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin

	t.Cleanup(func() { os.Stdin = oldStdin })

	os.Stdin = r

	go func() {
		defer w.Close() //nolint:errcheck // ok

		w.WriteString(testOTPSecret() + "\n") //nolint:errcheck,gosec // ok
	}()

	cli.prompt = func(label string, val *string) error {
		if label == "Username" {
			*val = "FromStdin"

			return nil
		}

		return errors.New("EOF")
	}
	if err = cli.otpAdd("", otpAddOpts{Issuer: "X", Period: "30", Algorithm: "sha1", Digits: "6"}); err != nil {
		t.Fatal(err)
	}

	if _, err = loadOTP("FromStdin"); err != nil {
		t.Fatal(err)
	}
}

func TestOTPCodeClipboardWarn(t *testing.T) {
	keyring.MockInit()

	entry := otpEntry{Username: "Clip", Secret: testOTPSecret()}
	if err := entry.store(); err != nil {
		t.Fatal(err)
	}

	origClip := clipboardWrite

	t.Cleanup(func() { clipboardWrite = origClip })

	clipboardWrite = func(string) error { return errors.New("no clip") }

	cli := app{}
	if err := cli.otpCode("Clip"); err != nil {
		t.Fatal(err)
	}
}

func TestPipeClipboard(t *testing.T) {
	if err := pipeClipboard("hello", "true"); err != nil {
		t.Fatal(err)
	}

	if err := pipeClipboard("hello", "false"); err == nil {
		t.Fatal("want false to fail")
	}

	if err := pipeClipboard("hello", "command-that-does-not-exist-zzzz"); err == nil {
		t.Fatal("want missing command error")
	}
}

func clipCall(name string, args ...string) string {
	if len(args) == 0 {
		return name
	}

	return name + " " + strings.Join(args, " ")
}

//nolint:funlen // ok
func TestClipboardWriteDefaultBranches(t *testing.T) {
	origGOOS, origRun := clipboardGOOS, runClipboard

	t.Cleanup(func() {
		clipboardGOOS = origGOOS
		runClipboard = origRun
	})

	runClipboard = func(string, string, ...string) error { return nil }

	for _, goos := range []string{"darwin", "windows"} {
		clipboardGOOS = goos

		if err := clipboardWriteDefault("x"); err != nil {
			t.Fatalf("%s: %v", goos, err)
		}
	}

	clipboardGOOS = "linux"

	t.Setenv("XDG_SESSION_TYPE", "wayland")

	var calls []string

	runClipboard = func(_, name string, args ...string) error {
		calls = append(calls, clipCall(name, args...))

		return nil
	}

	if err := clipboardWriteDefault("x"); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 1 || calls[0] != "wl-copy --primary" {
		t.Fatalf("wayland primary calls=%v", calls)
	}

	calls = nil
	n := 0
	runClipboard = func(_, name string, args ...string) error {
		n++

		calls = append(calls, clipCall(name, args...))

		if n == 1 {
			return errors.New("primary fail")
		}

		return nil
	}

	if err := clipboardWriteDefault("x"); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 2 || calls[1] != "wl-copy" {
		t.Fatalf("wayland fallback calls=%v", calls)
	}

	t.Setenv("XDG_SESSION_TYPE", "x11")

	calls = nil
	runClipboard = func(_, name string, args ...string) error {
		calls = append(calls, clipCall(name, args...))
		if name == "xclip" {
			return nil
		}

		return errors.New("nope")
	}

	if err := clipboardWriteDefault("x"); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 1 || !strings.HasPrefix(calls[0], "xclip ") {
		t.Fatalf("xclip calls=%v", calls)
	}

	calls = nil
	runClipboard = func(_, name string, args ...string) error {
		calls = append(calls, name)
		if name == "xsel" {
			return nil
		}

		return errors.New("nope")
	}

	if err := clipboardWriteDefault("x"); err != nil {
		t.Fatal(err)
	}

	if len(calls) != 2 || calls[1] != "xsel" {
		t.Fatalf("xsel calls=%v", calls)
	}

	runClipboard = func(string, string, ...string) error { return errors.New("nope") }

	if err := clipboardWriteDefault("x"); err == nil {
		t.Fatal("want no-helper error")
	}
}

func TestOTPErrorPaths(t *testing.T) {
	keyring.MockInit()

	if err := (otpEntry{Username: "x", Secret: "y", Period: "0"}).store(); err == nil {
		t.Fatal("want period 0 store error")
	}

	if err := keyring.Set(otpKeyringService, "bad", "{"); err != nil {
		t.Fatal(err)
	}

	if _, err := loadOTP("bad"); err == nil {
		t.Fatal("want decode error")
	}

	cli := app{}
	if err := cli.otpCode("missing"); err == nil {
		t.Fatal("want missing code error")
	}

	if err := cli.otpVerify("missing", "000000"); err == nil {
		t.Fatal("want missing verify error")
	}

	bad := otpEntry{Username: "BadOpts", Secret: testOTPSecret(), Period: "0"}

	b, err := json.Marshal(map[string]string{
		"Username": bad.Username, "Secret": bad.Secret, "Period": "0",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err = keyring.Set(otpKeyringService, bad.Username, string(b)); err != nil {
		t.Fatal(err)
	}

	if err = cli.otpCode(bad.Username); err == nil {
		t.Fatal("want code validateOpts error")
	}

	if err = cli.otpVerify(bad.Username, "000000"); err == nil {
		t.Fatal("want verify validateOpts error")
	}

	// Invalid base32 → GenerateCodeCustom / ValidateCustom errors.
	if err = keyring.Set(otpKeyringService, "NotB32", `{"Username":"NotB32","Secret":"!!!!","Period":"30","Algorithm":"sha1","Digits":"6"}`); err != nil {
		t.Fatal(err)
	}

	if err = cli.otpCode("NotB32"); err == nil {
		t.Fatal("want generate error")
	}

	if err = cli.otpVerify("NotB32", "000000"); err == nil {
		t.Fatal("want verify crypto error")
	}

	e := otpEntry{Username: "x", Secret: "y", Digits: "nope"}
	if err = e.validate(); err == nil {
		t.Fatal("want digits parse error")
	}
}

func TestOTPDeleteAbortAndMissing(t *testing.T) {
	keyring.MockInit()

	entry := otpEntry{Username: "Keep", Secret: testOTPSecret()}
	if err := entry.store(); err != nil {
		t.Fatal(err)
	}

	cli := app{prompt: func(_ string, val *string) error {
		*val = "n"

		return nil
	}}
	if err := cli.otpDelete("Keep"); err == nil {
		t.Fatal("want delete abort")
	}

	if _, err := loadOTP("Keep"); err != nil {
		t.Fatal(err)
	}

	cli.prompt = func(string, *string) error { return errors.New("EOF") }

	if err := cli.otpDelete("missing-otp"); err == nil {
		t.Fatal("want delete missing error")
	}
}

//nolint:funlen // ok
func TestOTPImportExportErrorsAndCommand(t *testing.T) {
	keyring.MockInit()

	cli := app{prompt: func(string, *string) error { return nil }}
	if err := cli.otpImport("/no/such/otp.json"); err == nil {
		t.Fatal("want import read error")
	}

	dir := t.TempDir()

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cli.otpImport(bad); err == nil {
		t.Fatal("want import decode error")
	}

	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`[{"username":"","secret":"x"}]`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cli.otpImport(invalid); err == nil {
		t.Fatal("want import validate error")
	}

	good := filepath.Join(dir, "good.json")
	sec := testOTPSecret()

	payload := `[{"username":"Imp","secret":"` + sec + `","issuer":"Imp","period":"30","algorithm":"sha1","digits":"6"}]`
	if err := os.WriteFile(good, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := cli.otpCommand([]string{"import", good}, otpAddOpts{}); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "out.json")
	if err := cli.otpCommand([]string{"export", out}, otpAddOpts{}); err != nil {
		t.Fatal(err)
	}

	if err := cli.otpCommand([]string{"list"}, otpAddOpts{}); err != nil {
		t.Fatal(err)
	}

	clipboardWrite = func(string) error { return nil }

	if err := cli.otpCommand([]string{"code", "Imp"}, otpAddOpts{}); err != nil {
		t.Fatal(err)
	}

	origTerm := stdoutIsTerminal

	t.Cleanup(func() { stdoutIsTerminal = origTerm })

	stdoutIsTerminal = func(int) bool { return true }

	if err := cli.otpExport(""); err == nil {
		t.Fatal("want TTY refuse")
	}

	if err := cli.otpExport(filepath.Join(dir, "no", "such", "out.json")); err == nil {
		t.Fatal("want export write error")
	}

	// Corrupt keyring value breaks export mid-loop.
	if err := keyring.Set(otpKeyringService, "Broken", "{"); err != nil {
		t.Fatal(err)
	}

	stdoutIsTerminal = func(int) bool { return false }

	if err := cli.otpExport(filepath.Join(dir, "fail.json")); err == nil {
		t.Fatal("want export load error")
	}
}

func TestOTPAddPromptErrorsAndOverwriteYes(t *testing.T) {
	keyring.MockInit()

	cli := app{prompt: func(string, *string) error { return errors.New("EOF") }}
	if err := cli.otpAdd("", otpAddOpts{}); err == nil {
		t.Fatal("want username prompt error")
	}

	entry := otpEntry{Username: "Over", Secret: testOTPSecret()}
	if err := entry.store(); err != nil {
		t.Fatal(err)
	}

	cli.prompt = func(label string, val *string) error {
		if strings.Contains(label, "overwrite") {
			return errors.New("EOF")
		}

		t.Fatalf("unexpected prompt %q", label)

		return nil
	}
	if err := cli.otpAdd("Over", otpAddOpts{}); err == nil {
		t.Fatal("want overwrite prompt-abort")
	}

	sec := testOTPSecret()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	oldStdin := os.Stdin

	t.Cleanup(func() { os.Stdin = oldStdin })

	os.Stdin = r

	go func() {
		defer w.Close() //nolint:errcheck // ok

		w.WriteString(sec + "\n") //nolint:errcheck,gosec // ok
	}()

	cli.prompt = func(label string, val *string) error {
		if strings.Contains(label, "overwrite") {
			*val = "yes"

			return nil
		}

		return errors.New("EOF")
	}
	if err = cli.otpAdd("Over", otpAddOpts{Issuer: "O", Period: "30", Algorithm: "sha1", Digits: "6"}); err != nil {
		t.Fatal(err)
	}
}
