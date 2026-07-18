package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/StevenBuglione/private-vm/internal/buildinfo"
)

func main() {
	var version bool
	var configPath string
	flag.BoolVar(&version, "version", false, "print build information")
	flag.StringVar(&configPath, "config", "/etc/private-vm/config.toml", "configuration file")
	flag.Parse()

	if version {
		_ = json.NewEncoder(os.Stdout).Encode(buildinfo.Current())
		return
	}

	fmt.Fprintf(os.Stderr,
		"private-vmd starter scaffold: daemon server is not implemented.\n"+
			"configuration path: %s\n"+
			"Implement Phase 3 in docs/25-implementation-roadmap.md.\n",
		configPath)
	os.Exit(20)
}
