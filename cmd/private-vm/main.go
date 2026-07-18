package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/preflight"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printHelp(stdout)
		return exitcode.OK
	}

	switch args[0] {
	case "help", "-h", "--help":
		printHelp(stdout)
		return exitcode.OK
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "desktop", "workspace", "run", "session", "images", "vpn", "usb", "config", "policy", "system", "completion", "plan":
		return notImplemented(args, stderr)
	default:
		fmt.Fprintf(stderr, "private-vm: unknown command %q\n\n", args[0])
		printHelp(stderr)
		return exitcode.Usage
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	jsonOutput, err := parseOnlyJSON(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitcode.Usage
	}
	info := buildinfo.Current()
	if jsonOutput {
		_ = json.NewEncoder(stdout).Encode(info)
		return exitcode.OK
	}
	fmt.Fprintf(stdout, "private-vm %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n",
		info.Version, info.Commit, info.Date, info.GoVersion, info.OS, info.Arch)
	return exitcode.OK
}

func runDoctor(args []string, stdout, stderr io.Writer) int {
	strict := false
	jsonOutput := false
	for _, arg := range args {
		switch arg {
		case "--strict":
			strict = true
		case "--json":
			jsonOutput = true
		default:
			fmt.Fprintf(stderr, "doctor: unknown option %q\n", arg)
			return exitcode.Usage
		}
	}
	report := (preflight.Doctor{Strict: strict}).Run()
	if jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		for _, d := range report.Diagnostics {
			fmt.Fprintf(stdout, "[%s] %s: %s\n", strings.ToUpper(string(d.Severity)), d.Code, d.Summary)
			if d.Remediation != "" {
				fmt.Fprintf(stdout, "  remediation: %s\n", d.Remediation)
			}
		}
		fmt.Fprintf(stdout, "\nrunnable: %t\n", report.Runnable)
	}
	if !report.Runnable {
		return exitcode.Preflight
	}
	return exitcode.OK
}

func parseOnlyJSON(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	if len(args) == 1 && args[0] == "--json" {
		return true, nil
	}
	return false, errors.New("only --json is supported")
}

func notImplemented(args []string, stderr io.Writer) int {
	fmt.Fprintf(stderr,
		"private-vm: command %q is specified but not implemented in the starter scaffold.\n"+
			"Follow docs/25-implementation-roadmap.md and project/backlog.yaml.\n",
		strings.Join(args, " "))
	return exitcode.Runtime
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `private-vm — disposable graphical private-workstation orchestrator

Usage:
  private-vm <command> [options]

Implemented in this starter:
  version [--json]          Print build information
  doctor [--strict] [--json]
                            Run initial host diagnostics

Specified for implementation:
  init
  plan
  desktop start|connect|status|stop|restart-viewer
  workspace import|inbox|list|inspect|export|verify|discard
  run workstation|torrent|scanner
  session list|status|report|stop|abort|cleanup
  images list|sync|pull|verify|inspect|build|test|prune
  vpn import|inspect|test|rotate|remove
  usb list|inspect|enroll|prepare|verify|forget
  config show|get|set|validate
  policy list|show|validate
  system status|install|uninstall
  completion bash|zsh|fish

Read START_HERE.md before implementation.
`)
}
