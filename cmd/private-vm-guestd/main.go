package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/session"
)

func main() {
	var role string
	var version bool
	flag.StringVar(&role, "role", "", "compiled guest role")
	flag.BoolVar(&version, "version", false, "print build information")
	flag.Parse()

	if version {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}

	switch session.Role(role) {
	case session.RoleWorkstation, session.RoleDownloader, session.RoleScanner, session.RoleExporter:
	default:
		fmt.Fprintln(os.Stderr, "private-vm-guestd: --role must be workstation, downloader, scanner, or exporter")
		os.Exit(2)
	}

	fmt.Fprintf(os.Stderr,
		"private-vm-guestd starter scaffold for role %s: VSOCK server is not implemented.\n"+
			"Implement Phase 2 and docs/09-rpc-protocol.md.\n",
		role)
	os.Exit(20)
}
