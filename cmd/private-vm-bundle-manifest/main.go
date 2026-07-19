package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/StevenBuglione/private-vm/internal/systeminstall"
)

func main() {
	var root, version string
	flag.StringVar(&root, "root", "", "generic archive staging root")
	flag.StringVar(&version, "version", "", "release version")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "private-vm-bundle-manifest: MANIFEST_BUILD_FAILED")
		os.Exit(1)
	}
	manifest, err := systeminstall.BuildManifest(context.Background(), root, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "private-vm-bundle-manifest: MANIFEST_BUILD_FAILED")
		os.Exit(1)
	}
	encoded, err := systeminstall.MarshalManifest(manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "private-vm-bundle-manifest: MANIFEST_BUILD_FAILED")
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		fmt.Fprintln(os.Stderr, "private-vm-bundle-manifest: MANIFEST_BUILD_FAILED")
		os.Exit(1)
	}
}
