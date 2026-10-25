package main

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/zalando/go-keyring"
)

type genericRef struct {
	Kind string
	Name string
	Src  string // File:line for migrate reporting.
	All  bool   // Name was dynamic; migrate every legacy user under Kind.
}

const genericKeyringService = "awbus-generic"

// awbusGetRE finds `awbus get <kind> <name>` even when awbus is invoked via a
// path or command substitution. Captures are raw tokens (cleaned later).
var awbusGetRE = regexp.MustCompile(`(?i)awbus\s+get\s+(\S+)\s+(\S+)`)

func genericKey(kind, name string) string {
	return kind + "/" + name
}

func getGeneric(kind, name string) (secret string, err error) {
	secret, err = keyring.Get(genericKeyringService, genericKey(kind, name))
	if err == nil || !errors.Is(err, keyring.ErrNotFound) {
		return
	}

	// Legacy layout: keyring service = kind, username = name.
	return keyring.Get(kind, name)
}

func putGeneric(kind, name, secret string) (err error) {
	if err = keyring.Set(genericKeyringService, genericKey(kind, name), secret); err != nil {
		return
	}

	// Best-effort cleanup of the pre-awbus-generic location.
	if delErr := keyring.Delete(kind, name); delErr != nil && !errors.Is(delErr, keyring.ErrNotFound) {
		return fmt.Errorf("stored under %s but failed to delete legacy %s/%s: %w",
			genericKeyringService, kind, name, delErr)
	}

	return
}

func listUsers(service string) (users []string, err error) {
	users, err = keyring.ListUsers(service)
	if err != nil {
		return nil, fmt.Errorf("list %q: %w", service, err)
	}

	sort.Strings(users)

	return users, nil
}

func printListSection(title, service string) (err error) {
	users, err := listUsers(service)
	if err != nil {
		return
	}

	fmt.Printf("%s (%s):\n", title, service)

	if len(users) == 0 {
		fmt.Println("  (none)")

		return
	}

	for _, u := range users {
		fmt.Printf("  %s\n", u)
	}

	return
}

// printListNames prints one username per line with no header or indent.
// Used by list-* / otp list so the output is shell-friendly.
func printListNames(service string) (err error) {
	users, err := listUsers(service)
	if err != nil {
		return
	}

	for _, u := range users {
		fmt.Println(u)
	}

	return
}

func (a *app) listAll() (err error) {
	sections := []struct{ title, service string }{
		{"profiles", keyringService},
		{"sts-url", stsURLKeyringService},
		{"cognito", cognitoKeyringService},
		{"jwt", jwtKeyringService},
		{"generic", genericKeyringService},
		{"otp", otpKeyringService},
	}

	for i, s := range sections {
		if err = printListSection(s.title, s.service); err != nil {
			return
		}

		if i < len(sections)-1 {
			fmt.Println()
		}
	}

	return
}

func migrateGenericPair(kind, name string) (err error) {
	key := genericKey(kind, name)

	_, err = keyring.Get(genericKeyringService, key)
	switch {
	case err == nil:
		// Already under awbus-generic; still drop a leftover legacy entry.
		if delErr := keyring.Delete(kind, name); delErr != nil && !errors.Is(delErr, keyring.ErrNotFound) {
			return delErr
		}

		return nil
	case errors.Is(err, keyring.ErrNotFound):
		// Continue with legacy read below.
	default:
		return fmt.Errorf("check %s/%s: %w", genericKeyringService, key, err)
	}

	secret, err := keyring.Get(kind, name)
	if err != nil {
		return fmt.Errorf("legacy %s/%s: %w", kind, name, err)
	}

	return putGeneric(kind, name, secret)
}

func stripToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "\"'),;`]")
	s = strings.TrimLeft(s, "\"'`")

	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}

	return s
}

func isDynamicToken(s string) bool {
	return strings.ContainsAny(s, "$`") || strings.Contains(s, "$(")
}

func parseAwbusGets(path string, data []byte) (refs []genericRef, skipped []string) {
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0

	for sc.Scan() {
		lineNo++
		line := sc.Text()

		for _, m := range awbusGetRE.FindAllStringSubmatch(line, -1) {
			kind, name := stripToken(m[1]), stripToken(m[2])
			src := fmt.Sprintf("%s:%d", path, lineNo)

			switch {
			case kind == "" || name == "":
				skipped = append(skipped, fmt.Sprintf("%s: empty get (%s %s)", src, m[1], m[2]))
			case isDynamicToken(kind):
				// Kind must be static — we key legacy ListUsers off it.
				skipped = append(skipped, fmt.Sprintf("%s: dynamic kind (%s %s)", src, m[1], m[2]))
			case isDynamicToken(name):
				// Dynamic name (awbus get ssh $i): migrate every legacy user under kind.
				refs = append(refs, genericRef{Kind: kind, Name: "*", Src: src, All: true})
			default:
				refs = append(refs, genericRef{Kind: kind, Name: name, Src: src})
			}
		}
	}

	return refs, skipped
}

// expandDynamicRefs turns All refs into concrete kind/name pairs via ListUsers
// on the legacy keyring service (the static kind).
func expandDynamicRefs(refs []genericRef) (out []genericRef, err error) {
	type pair struct{ kind, name string }

	seen := map[pair]struct{}{}

	add := func(r genericRef) {
		k := pair{r.Kind, r.Name}
		if _, ok := seen[k]; ok {
			return
		}

		seen[k] = struct{}{}

		out = append(out, r)
	}

	for _, r := range refs {
		if !r.All {
			add(r)

			continue
		}

		var users []string

		users, err = keyring.ListUsers(r.Kind)
		if err != nil {
			return nil, fmt.Errorf("list legacy %q (from %s): %w", r.Kind, r.Src, err)
		}

		if len(users) == 0 {
			fmt.Fprintf(os.Stderr, "awbus: no legacy secrets under %q (from %s)\n", r.Kind, r.Src)
			continue
		}

		for _, u := range users {
			add(genericRef{
				Kind: r.Kind,
				Name: u,
				Src:  fmt.Sprintf("%s → list %s", r.Src, r.Kind),
			})
		}
	}

	slices.SortFunc(out, func(a, b genericRef) int {
		if a.Kind != b.Kind {
			return strings.Compare(a.Kind, b.Kind)
		}

		return strings.Compare(a.Name, b.Name)
	})

	return out, nil
}

func defaultMigrateRoots() (roots []string) {
	home, _ := os.UserHomeDir() //nolint:errcheck // ok
	shell := filepath.Base(os.Getenv("SHELL"))

	switch shell {
	case "zsh":
		zdot := cmpOrEnv("ZDOTDIR", home)
		roots = append(roots,
			filepath.Join(zdot, ".zshrc"),
			filepath.Join(zdot, ".zshenv"),
			filepath.Join(zdot, ".zprofile"),
			filepath.Join(zdot, ".zlogin"),
		)
	case "bash":
		roots = append(roots,
			filepath.Join(home, ".bashrc"),
			filepath.Join(home, ".bash_profile"),
			filepath.Join(home, ".profile"),
		)
		if v := os.Getenv("BASH_ENV"); v != "" {
			roots = append(roots, v)
		}
	case "fish":
		cfg := filepath.Join(cmpOrEnv("XDG_CONFIG_HOME", filepath.Join(home, ".config")), "fish")
		roots = append(roots, filepath.Join(cfg, "config.fish"))
	default:
		roots = append(roots,
			filepath.Join(home, ".profile"),
			filepath.Join(home, ".bashrc"),
			filepath.Join(home, ".zshrc"),
		)
	}

	return roots
}

func cmpOrEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}

func collectMigrateFiles(extra []string) ([]string, error) {
	var files []string

	seen := map[string]struct{}{}
	add := func(path string) {
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}

		seen[path] = struct{}{}
		files = append(files, path)
	}

	candidates := append(defaultMigrateRoots(), extra...)
	for _, candidate := range candidates {
		if err := addMigrateCandidate(candidate, add); err != nil {
			return nil, err
		}
	}

	sort.Strings(files)

	return files, nil
}

func addMigrateCandidate(candidate string, add func(string)) (err error) {
	info, err := os.Stat(candidate) //nolint:gosec // ok
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	if !info.IsDir() {
		add(candidate)

		return nil
	}

	return filepath.WalkDir(candidate, func(path string, d fs.DirEntry, walkErr error) error { //nolint:gosec // ok
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "node_modules" {
				return fs.SkipDir
			}

			return nil
		}

		name := strings.ToLower(d.Name())
		if strings.HasSuffix(name, ".db") || strings.HasSuffix(name, ".sqlite") {
			return nil
		}

		add(path)

		return nil
	})
}

func discoverGenericRefs(extraPaths []string) (refs []genericRef, skipped, files []string, err error) {
	files, err = collectMigrateFiles(extraPaths)
	if err != nil {
		return
	}

	type pair struct {
		kind, name string
		all        bool
	}

	seen := map[pair]string{} // First source wins.

	for _, path := range files {
		var data []byte

		data, err = os.ReadFile(path) //nolint:gosec // ok
		if err != nil {
			return
		}

		found, skip := parseAwbusGets(path, data)
		skipped = append(skipped, skip...)

		for _, r := range found {
			k := pair{r.Kind, r.Name, r.All}
			if _, ok := seen[k]; ok {
				continue
			}

			seen[k] = r.Src
			refs = append(refs, r)
		}
	}

	refs, err = expandDynamicRefs(refs)
	if err != nil {
		return
	}

	return refs, skipped, files, nil
}

func (a *app) migrateFromConfigs(extraPaths []string) (err error) {
	refs, skipped, files, err := discoverGenericRefs(extraPaths)
	if err != nil {
		return
	}

	fmt.Fprintf(os.Stderr, "awbus: scanned %d file(s) for `awbus get`\n", len(files))

	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "awbus: skip %s\n", s)
	}

	if len(refs) == 0 {
		fmt.Fprintln(os.Stderr, "awbus: nothing to migrate")

		return nil
	}

	fmt.Fprintln(os.Stderr, "awbus: will migrate:")

	for _, r := range refs {
		fmt.Fprintf(os.Stderr, "  %s/%s  (from %s)\n", r.Kind, r.Name, r.Src)
	}

	var answer string

	prompt := fmt.Sprintf("Migrate %d secret(s) into %q? [y/N]", len(refs), genericKeyringService)
	if promptErr := a.prompt(prompt, &answer); promptErr != nil {
		return errors.New("aborted: migrate not confirmed")
	}

	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return errors.New("aborted: migrate not confirmed")
	}

	var migrated, missing int

	for _, r := range refs {
		migErr := migrateGenericPair(r.Kind, r.Name)
		if migErr != nil {
			if errors.Is(migErr, keyring.ErrNotFound) || strings.Contains(migErr.Error(), "secret not found") {
				fmt.Fprintf(os.Stderr, "awbus: missing legacy secret %s/%s\n", r.Kind, r.Name)

				missing++

				continue
			}

			return migErr
		}

		migrated++

		fmt.Fprintf(os.Stderr, "awbus: migrated %s/%s\n", r.Kind, r.Name)
	}

	fmt.Fprintf(os.Stderr, "awbus: done (%d migrated, %d missing)\n", migrated, missing)

	return nil
}
