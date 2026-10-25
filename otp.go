package main

import (
	"cmp"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/zalando/go-keyring"
	"golang.org/x/term"
)

// otpEntry is the keyring JSON shape (PascalCase, house style).
type otpEntry struct {
	Username  string `json:"Username"`
	Secret    string `json:"Secret"`
	Issuer    string `json:"Issuer"`
	Period    string `json:"Period"`
	Algorithm string `json:"Algorithm"`
	Digits    string `json:"Digits"`
}

// otpFileEntry matches the legacy otp.json array format (lowercase keys).
type otpFileEntry struct {
	Username  string `json:"username"`  //nolint:tagliatelle // legacy otp.json
	Secret    string `json:"secret"`    //nolint:tagliatelle // legacy otp.json
	Issuer    string `json:"issuer"`    //nolint:tagliatelle // legacy otp.json
	Period    string `json:"period"`    //nolint:tagliatelle // legacy otp.json
	Algorithm string `json:"algorithm"` //nolint:tagliatelle // legacy otp.json
	Digits    string `json:"digits"`    //nolint:tagliatelle // legacy otp.json
}

type otpAddOpts struct {
	Name, Issuer, Period, Algorithm, Digits string
}

const (
	otpKeyringService = "awbus-otp"
	otpDigitsSix      = 6
	otpDigitsEight    = 8
	otpExportMode     = 0o600
)

// stdoutIsTerminal is a seam so otp export's TTY refusal is testable.
var stdoutIsTerminal = term.IsTerminal //nolint:gochecknoglobals // ok

func (e otpEntry) toFile() otpFileEntry {
	return otpFileEntry(e)
}

func (f otpFileEntry) toEntry() otpEntry {
	return otpEntry(f)
}

func (e otpEntry) withDefaults() otpEntry {
	e.Period = cmp.Or(e.Period, "30")
	e.Algorithm = cmp.Or(e.Algorithm, "sha1")
	e.Digits = cmp.Or(e.Digits, "6")

	if e.Issuer == "" {
		e.Issuer = e.Username
	}

	return e
}

func (e otpEntry) validate() error {
	if e.Username == "" {
		return errors.New("otp entry username is required")
	}

	if e.Secret == "" {
		return errors.New("otp entry secret is required")
	}

	if _, err := e.validateOpts(); err != nil {
		return err
	}

	return nil
}

func (e otpEntry) validateOpts() (opts totp.ValidateOpts, err error) {
	period, err := strconv.ParseUint(cmp.Or(e.Period, "30"), 10, 32)
	if err != nil || period == 0 {
		return opts, fmt.Errorf("invalid period %q: %w", e.Period, err)
	}

	digits, err := strconv.Atoi(cmp.Or(e.Digits, "6"))
	if err != nil {
		return opts, fmt.Errorf("invalid digits %q: %w", e.Digits, err)
	}

	dig, err := otpDigits(digits)
	if err != nil {
		return opts, err
	}

	algo, err := otpAlgorithm(cmp.Or(e.Algorithm, "sha1"))
	if err != nil {
		return opts, err
	}

	return totp.ValidateOpts{
		Period:    uint(period),
		Skew:      1,
		Digits:    dig,
		Algorithm: algo,
	}, nil
}

func otpDigits(n int) (otp.Digits, error) {
	switch n {
	case otpDigitsSix:
		return otp.DigitsSix, nil
	case otpDigitsEight:
		return otp.DigitsEight, nil
	default:
		return 0, fmt.Errorf("unsupported digits %d (want 6 or 8)", n)
	}
}

func otpAlgorithm(name string) (otp.Algorithm, error) {
	switch strings.ToLower(name) {
	case "sha1":
		return otp.AlgorithmSHA1, nil
	case "sha256":
		return otp.AlgorithmSHA256, nil
	case "sha512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", name)
	}
}

func (e otpEntry) store() error {
	e = e.withDefaults()

	if err := e.validate(); err != nil {
		return err
	}

	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal otp entry: %w", err)
	}

	if err = keyring.Set(otpKeyringService, e.Username, string(b)); err != nil {
		return fmt.Errorf("store otp %q: %w", e.Username, err)
	}

	return nil
}

func loadOTP(name string) (e otpEntry, err error) {
	raw, err := keyring.Get(otpKeyringService, name)
	if err != nil {
		return e, fmt.Errorf("load otp %q: %w", name, err)
	}

	if err = json.Unmarshal([]byte(raw), &e); err != nil {
		return e, fmt.Errorf("decode otp %q: %w", name, err)
	}

	e.Username = cmp.Or(e.Username, name)
	e = e.withDefaults()

	return e, nil
}

func (a *app) otpCommand(args []string, add otpAddOpts) (err error) {
	if len(args) < 1 {
		return errors.New("otp requires a subcommand (code|verify|list|add|delete|import|export)")
	}

	switch args[0] {
	case "code":
		if len(args) < 2 {
			return errors.New("otp code requires a name")
		}

		return a.otpCode(args[1])
	case "verify":
		if len(args) < 3 { //nolint:mnd // ok
			return errors.New("otp verify requires a name and a code")
		}

		return a.otpVerify(args[1], args[2])
	case "list":
		return printListNames(otpKeyringService)
	case "add":
		name := add.Name
		if len(args) >= 2 {
			name = args[1]
		}

		return a.otpAdd(name, add)
	case "delete":
		if len(args) < 2 {
			return errors.New("otp delete requires a name")
		}

		return a.otpDelete(args[1])
	case "import":
		if len(args) < 2 {
			return errors.New("otp import requires a file path")
		}

		return a.otpImport(args[1])
	case "export":
		path := ""
		if len(args) >= 2 {
			path = args[1]
		}

		return a.otpExport(path)
	default:
		return fmt.Errorf("unknown otp subcommand %q", args[0])
	}
}

func (a *app) otpCode(name string) (err error) {
	e, err := loadOTP(name)
	if err != nil {
		return
	}

	opts, err := e.validateOpts()
	if err != nil {
		return
	}

	code, err := totp.GenerateCodeCustom(e.Secret, time.Now(), opts)
	if err != nil {
		return fmt.Errorf("generate otp code: %w", err)
	}

	if clipErr := clipboardWrite(code); clipErr != nil {
		fmt.Fprintln(os.Stderr, "WARN: could not copy to clipboard:", clipErr)
	}

	fmt.Println(name, "OK")

	return
}

func (a *app) otpVerify(name, code string) (err error) {
	e, err := loadOTP(name)
	if err != nil {
		return
	}

	opts, err := e.validateOpts()
	if err != nil {
		return
	}

	ok, err := totp.ValidateCustom(code, e.Secret, time.Now().UTC(), opts)
	if err != nil {
		return fmt.Errorf("verify otp: %w", err)
	}

	fmt.Println(ok)

	return
}

func (a *app) otpAdd(name string, add otpAddOpts) error {
	entry := otpEntry{
		Username:  name,
		Issuer:    add.Issuer,
		Period:    add.Period,
		Algorithm: add.Algorithm,
		Digits:    add.Digits,
	}

	if err := a.promptIfEmpty("Username", &entry.Username); err != nil {
		return err
	}

	ok, err := a.confirmOTPOverwrite(entry.Username)
	if err != nil {
		return err
	}

	if !ok {
		return fmt.Errorf("aborted: otp %q already exists", entry.Username)
	}

	a.promptOptional("Issuer", &entry.Issuer)
	a.promptOptional("Period", &entry.Period)
	a.promptOptional("Algorithm", &entry.Algorithm)
	a.promptOptional("Digits", &entry.Digits)

	secret, err := a.readOTPSecret()
	if err != nil {
		return err
	}

	entry.Secret = secret

	return entry.store()
}

// promptOptional prompts when val is empty; empty Enter leaves val unchanged.
func (a *app) promptOptional(label string, val *string) {
	if *val != "" {
		return
	}

	// Empty Enter from Scanln is intentional "use default".
	if err := a.prompt(label, val); err != nil {
		return
	}
}

func (a *app) readOTPSecret() (string, error) {
	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		input, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return "", fmt.Errorf("read otp secret from stdin: %w", readErr)
		}

		return strings.TrimRight(string(input), "\r\n"), nil
	}

	var secret string
	if promptErr := a.prompt("Secret", &secret); promptErr != nil {
		return "", promptErr
	}

	return secret, nil
}

func (a *app) confirmOTPOverwrite(name string) (ok bool, err error) {
	if _, err = keyring.Get(otpKeyringService, name); errors.Is(err, keyring.ErrNotFound) {
		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("check existing otp %q: %w", name, err)
	}

	var answer string

	if promptErr := a.prompt(fmt.Sprintf("OTP %q exists; overwrite? [y/N]", name), &answer); promptErr != nil {
		return false, nil //nolint:nilerr // ok
	}

	answer = strings.ToLower(strings.TrimSpace(answer))

	return answer == "y" || answer == "yes", nil
}

func (a *app) otpDelete(name string) (err error) {
	var answer string

	if promptErr := a.prompt(fmt.Sprintf("Delete otp %q? [Enter/y to confirm]", name), &answer); promptErr == nil {
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			return fmt.Errorf("aborted: otp %q not deleted", name)
		}
	}

	if err = keyring.Delete(otpKeyringService, name); err != nil {
		return fmt.Errorf("delete otp %q: %w", name, err)
	}

	return
}

func (a *app) otpImport(path string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // ok
	if err != nil {
		return fmt.Errorf("read otp import %q: %w", path, err)
	}

	var fileEntries []otpFileEntry
	if err = json.Unmarshal(raw, &fileEntries); err != nil {
		return fmt.Errorf("decode otp import %q: %w", path, err)
	}

	var imported, skipped int

	for _, fe := range fileEntries {
		e := fe.toEntry().withDefaults()

		if err = e.validate(); err != nil {
			return fmt.Errorf("otp import entry %q: %w", e.Username, err)
		}

		ok, confirmErr := a.confirmOTPOverwrite(e.Username)
		if confirmErr != nil {
			return confirmErr
		}

		if !ok {
			fmt.Fprintf(os.Stderr, "awbus: skip otp %q (exists)\n", e.Username)

			skipped++

			continue
		}

		if storeErr := e.store(); storeErr != nil {
			return storeErr
		}

		imported++

		fmt.Fprintf(os.Stderr, "awbus: imported otp %q\n", e.Username)
	}

	fmt.Fprintf(os.Stderr, "awbus: otp import done (%d imported, %d skipped)\n", imported, skipped)

	return nil
}

func (a *app) otpExport(path string) (err error) {
	names, err := listUsers(otpKeyringService)
	if err != nil {
		return
	}

	fileEntries := make([]otpFileEntry, 0, len(names))

	for _, name := range names {
		var e otpEntry

		e, err = loadOTP(name)
		if err != nil {
			return
		}

		fileEntries = append(fileEntries, e.toFile())
	}

	out, err := json.Marshal(fileEntries)
	if err != nil {
		return fmt.Errorf("marshal otp export: %w", err)
	}

	out = append(out, '\n')

	if path == "" {
		if stdoutIsTerminal(int(os.Stdout.Fd())) {
			return errors.New("otp export to a TTY refused; pass a file path")
		}

		_, err = os.Stdout.Write(out)

		return err
	}

	if err = os.WriteFile(path, out, otpExportMode); err != nil { //nolint:gosec // ok
		return fmt.Errorf("write otp export %q: %w", path, err)
	}

	fmt.Fprintf(os.Stderr, "awbus: exported %d otp entries to %s\n", len(fileEntries), path)

	return nil
}
