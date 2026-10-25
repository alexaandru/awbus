package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// clipboardWrite copies s to the system clipboard. Overridable in tests.
var clipboardWrite = clipboardWriteDefault //nolint:gochecknoglobals // ok

// Test seams for clipboardWriteDefault branches.
var (
	clipboardGOOS = runtime.GOOS  //nolint:gochecknoglobals // ok
	runClipboard  = pipeClipboard //nolint:gochecknoglobals // ok
)

func clipboardWriteDefault(s string) error {
	switch clipboardGOOS {
	case "darwin":
		return runClipboard(s, "pbcopy")
	case "windows":
		return runClipboard(s, "clip")
	default:
		if strings.EqualFold(os.Getenv("XDG_SESSION_TYPE"), "wayland") {
			if err := runClipboard(s, "wl-copy", "--primary"); err == nil {
				return nil
			}

			if err := runClipboard(s, "wl-copy"); err == nil {
				return nil
			}
		}

		if err := runClipboard(s, "xclip", "-selection", "clipboard"); err == nil {
			return nil
		}

		if err := runClipboard(s, "xsel", "--clipboard", "--input"); err == nil {
			return nil
		}

		return errors.New("no clipboard helper found (tried wl-copy, xclip, xsel)")
	}
}

func pipeClipboard(s, name string, args ...string) error {
	cmd := exec.CommandContext(context.Background(), name, args...) //nolint:gosec // ok
	cmd.Stdin = strings.NewReader(s)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	return nil
}
