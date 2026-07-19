// Command private-vm-release-acceptance runs the fixed source-only release
// matrix and writes redacted JSON/JUnit evidence. It intentionally exits
// nonzero while any live publication or clean-room gate is unavailable.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	privaterelease "github.com/StevenBuglione/private-vm/internal/release"
)

func main() {
	var workDir, jsonPath, junitPath string
	flag.StringVar(&workDir, "workdir", "", "official source checkout")
	flag.StringVar(&jsonPath, "json", "", "new redacted JSON evidence path")
	flag.StringVar(&junitPath, "junit", "", "new redacted JUnit evidence path")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "RELEASE_INVALID: unsupported acceptance arguments")
		os.Exit(1)
	}
	if err := privaterelease.RunSourceAcceptance(context.Background(), workDir, jsonPath, junitPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
