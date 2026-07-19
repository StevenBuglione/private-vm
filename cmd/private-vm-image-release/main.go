// Command private-vm-image-release is the narrow, non-interactive REL-003
// producer. It has no arbitrary registry, Nix, shell, credential-store or OCI
// graph surface: prepare, publish and anonymous verification all enforce the
// frozen image package contract in internal/image.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/secret"
)

const maxTokenBytes = 64 << 10

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdin io.Reader, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: private-vm-image-release <prepare|publish|verify-anonymous>")
	}
	switch arguments[0] {
	case "prepare":
		return runPrepare(ctx, arguments[1:], stdout)
	case "publish":
		return runPublish(ctx, arguments[1:], stdin, stdout)
	case "verify-anonymous":
		return runVerifyAnonymous(ctx, arguments[1:], stdout)
	default:
		return errors.New("unsupported private-vm image release operation")
	}
}

func runPrepare(ctx context.Context, arguments []string, stdout io.Writer) error {
	set := flag.NewFlagSet("prepare", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var options image.PrepareOptions
	var githubOutput string
	set.StringVar(&options.WorkDir, "workdir", "", "checked-out source directory")
	set.StringVar(&options.OutputDir, "output", "", "new private output directory")
	set.StringVar(&options.ImageTarget, "image-target", "", "exact Nix image output")
	set.StringVar(&options.ClosureTarget, "closure-target", "", "exact Nix runtime closure output")
	set.StringVar(&options.ReleaseTag, "tag", "", "canonical release tag")
	set.StringVar(&options.Role, "role", "", "guest role")
	set.StringVar(&options.Bundle, "bundle", "", "workstation bundle")
	set.StringVar(&options.Repository, "repository", "", "exact GHCR repository")
	set.StringVar(&options.SourceRepository, "source-repository", "", "exact source repository")
	set.StringVar(&options.SourceCommit, "source-commit", "", "exact source commit")
	set.StringVar(&options.SourceRef, "source-ref", "", "exact source ref")
	set.StringVar(&options.Workflow, "workflow", "", "exact workflow path")
	set.StringVar(&options.RepositoryID, "repository-id", "", "immutable GitHub repository ID")
	set.StringVar(&options.OwnerID, "owner-id", "", "immutable GitHub owner ID")
	set.StringVar(&options.RunID, "run-id", "", "GitHub run ID")
	set.StringVar(&options.RunAttempt, "run-attempt", "", "GitHub run attempt")
	set.StringVar(&githubOutput, "github-output", "", "GitHub output file")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("IMAGE_RELEASE_INVALID: prepare flags are incomplete or invalid")
	}
	result, err := image.PrepareRelease(ctx, options)
	if err != nil {
		return err
	}
	if githubOutput == "" {
		return errors.New("IMAGE_RELEASE_INVALID: --github-output is required")
	}
	output, err := os.OpenFile(githubOutput, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return errors.New("IMAGE_RELEASE_INVALID: GitHub output file is unavailable")
	}
	_, writeErr := fmt.Fprintf(output, "subject_digest=%s\npredicate_path=%s\nprepared_directory=%s\n", result.Receipt.ImageDigest, result.PredicatePath, options.OutputDir)
	closeErr := output.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("IMAGE_RELEASE_INVALID: GitHub output could not be written")
	}
	return writeJSON(stdout, result.Receipt)
}

func runPublish(ctx context.Context, arguments []string, stdin io.Reader, stdout io.Writer) error {
	set := flag.NewFlagSet("publish", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var options image.PublishOptions
	var tokenStdin bool
	set.StringVar(&options.Directory, "prepared", "", "prepared release directory")
	set.StringVar(&options.ProvenancePath, "provenance", "", "local actions/attest bundle")
	set.StringVar(&options.Repository, "repository", "", "exact GHCR repository")
	set.StringVar(&options.ReleaseTag, "tag", "", "canonical release version tag")
	set.StringVar(&options.Username, "username", "", "GitHub actor")
	set.BoolVar(&tokenStdin, "token-stdin", false, "read one bounded registry token from stdin")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || !tokenStdin {
		return errors.New("IMAGE_RELEASE_INVALID: publish requires exact flags and --token-stdin")
	}
	value, err := io.ReadAll(io.LimitReader(stdin, maxTokenBytes+1))
	if err != nil || len(value) == 0 || len(value) > maxTokenBytes || bytes.IndexByte(value, '\r') >= 0 || bytes.IndexByte(value, '\n') >= 0 {
		clear(value)
		return errors.New("IMAGE_RELEASE_INVALID: registry credential is empty, malformed, or exceeds its bound")
	}
	token, err := secret.New(value)
	clear(value)
	if err != nil {
		return errors.New("IMAGE_RELEASE_INVALID: registry credential could not be protected")
	}
	defer token.Destroy()
	options.Token = token
	result, err := image.PublishRelease(ctx, options)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runVerifyAnonymous(ctx context.Context, arguments []string, stdout io.Writer) error {
	set := flag.NewFlagSet("verify-anonymous", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var options image.AnonymousVerifyOptions
	set.StringVar(&options.Repository, "repository", "", "exact public GHCR repository")
	set.StringVar(&options.ReleaseTag, "tag", "", "canonical release version tag")
	set.StringVar(&options.Role, "role", "", "guest role")
	set.StringVar(&options.Bundle, "bundle", "", "workstation bundle")
	set.DurationVar(&options.Timeout, "timeout", 30*time.Minute, "bounded verification timeout")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("IMAGE_RELEASE_INVALID: anonymous verification flags are incomplete or invalid")
	}
	entry, err := image.VerifyAnonymousRelease(ctx, options)
	if err != nil {
		return err
	}
	return writeJSON(stdout, struct {
		SchemaVersion int    `json:"schema_version"`
		Project       string `json:"project"`
		Verified      bool   `json:"verified"`
		Digest        string `json:"manifest_digest"`
	}{SchemaVersion: 1, Project: "private-vm", Verified: true, Digest: entry.ManifestDigest})
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
