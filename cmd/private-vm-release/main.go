// Command private-vm-release is the narrow REL-004 whole-release coordinator.
// It accepts no arbitrary build command, repository, workflow or upload URL.
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

	privaterelease "github.com/StevenBuglione/private-vm/internal/release"
	"github.com/StevenBuglione/private-vm/internal/secret"
)

const maximumTokenBytes = 64 << 10

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdin, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, stdin io.Reader, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: private-vm-release <prepare|publish|verify>")
	}
	switch arguments[0] {
	case "prepare":
		return runPrepare(ctx, arguments[1:], stdout)
	case "publish":
		return runPublish(ctx, arguments[1:], stdin, stdout)
	case "verify":
		return runVerify(ctx, arguments[1:], stdout)
	default:
		return errors.New("RELEASE_INVALID: unsupported release operation")
	}
}

func runPrepare(ctx context.Context, arguments []string, stdout io.Writer) error {
	set := flag.NewFlagSet("prepare", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var options privaterelease.PrepareOptions
	var githubOutput string
	set.StringVar(&options.WorkDir, "workdir", "", "official source checkout")
	set.StringVar(&options.OutputDir, "output", "", "private staging directory")
	set.StringVar(&options.DEBPath, "deb", "", "exact DEB output")
	set.StringVar(&options.RPMPath, "rpm", "", "exact RPM output")
	set.StringVar(&options.GenericPath, "generic", "", "exact generic archive")
	set.StringVar(&options.ReleaseTag, "tag", "", "canonical release tag")
	set.StringVar(&options.SourceCommit, "source-commit", "", "tag commit")
	set.StringVar(&options.SourceRef, "source-ref", "", "tag ref")
	set.StringVar(&options.RepositoryID, "repository-id", "", "immutable repository ID")
	set.StringVar(&options.OwnerID, "owner-id", "", "immutable owner ID")
	set.StringVar(&options.RunID, "run-id", "", "workflow run ID")
	set.StringVar(&options.RunAttempt, "run-attempt", "", "workflow attempt")
	set.DurationVar(&options.Timeout, "timeout", privaterelease.DefaultTimeout, "bounded preparation timeout")
	set.StringVar(&githubOutput, "github-output", "", "GitHub output file")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || githubOutput == "" {
		return errors.New("RELEASE_INVALID: prepare flags are incomplete")
	}
	result, err := privaterelease.Prepare(ctx, options)
	if err != nil {
		return err
	}
	output, err := os.OpenFile(githubOutput, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return errors.New("RELEASE_INVALID: GitHub output file is unavailable")
	}
	_, writeErr := fmt.Fprintf(output,
		"prepared_directory=%s\ndeb_subject=%s\ndeb_digest=%s\ndeb_predicate=%s\nrpm_subject=%s\nrpm_digest=%s\nrpm_predicate=%s\ngeneric_subject=%s\ngeneric_digest=%s\ngeneric_predicate=%s\n",
		result.Directory,
		result.Index.Packages[0].File, result.Index.Packages[0].SHA256, result.Predicates[privaterelease.ArtifactDEB],
		result.Index.Packages[1].File, result.Index.Packages[1].SHA256, result.Predicates[privaterelease.ArtifactRPM],
		result.Index.Packages[2].File, result.Index.Packages[2].SHA256, result.Predicates[privaterelease.ArtifactGeneric],
	)
	closeErr := output.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("RELEASE_INVALID: GitHub output could not be written")
	}
	return writeJSON(stdout, result.Index)
}

func runPublish(ctx context.Context, arguments []string, stdin io.Reader, stdout io.Writer) error {
	set := flag.NewFlagSet("publish", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var options privaterelease.PublishOptions
	var deb, rpm, generic string
	var tokenStdin bool
	set.StringVar(&options.Directory, "prepared", "", "prepared release directory")
	set.StringVar(&options.ReleaseTag, "tag", "", "canonical release tag")
	set.StringVar(&options.SourceCommit, "source-commit", "", "tag commit")
	set.StringVar(&deb, "deb-provenance", "", "DEB attestation bundle")
	set.StringVar(&rpm, "rpm-provenance", "", "RPM attestation bundle")
	set.StringVar(&generic, "generic-provenance", "", "generic attestation bundle")
	set.BoolVar(&tokenStdin, "token-stdin", false, "read bounded token from stdin")
	set.DurationVar(&options.Timeout, "timeout", privaterelease.DefaultTimeout, "bounded publication timeout")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 || !tokenStdin || deb == "" || rpm == "" || generic == "" {
		return errors.New("RELEASE_INVALID: publish requires exact provenance flags and --token-stdin")
	}
	value, err := io.ReadAll(io.LimitReader(stdin, maximumTokenBytes+1))
	if err != nil || len(value) == 0 || len(value) > maximumTokenBytes || bytes.ContainsAny(value, "\r\n") {
		clear(value)
		return errors.New("RELEASE_INVALID: workflow credential is malformed or outside its bound")
	}
	token, err := secret.New(value)
	clear(value)
	if err != nil {
		return errors.New("RELEASE_INVALID: workflow credential could not be protected")
	}
	defer token.Destroy()
	options.Token = token
	options.Provenance = map[privaterelease.ArtifactKind]string{
		privaterelease.ArtifactDEB: deb, privaterelease.ArtifactRPM: rpm, privaterelease.ArtifactGeneric: generic,
	}
	result, err := privaterelease.Publish(ctx, options)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func runVerify(ctx context.Context, arguments []string, stdout io.Writer) error {
	set := flag.NewFlagSet("verify", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var options privaterelease.VerifyOptions
	set.StringVar(&options.ReleaseTag, "tag", "", "canonical release tag")
	set.StringVar(&options.SourceCommit, "source-commit", "", "tag commit")
	set.DurationVar(&options.Timeout, "timeout", 45*time.Minute, "bounded anonymous verification timeout")
	if err := set.Parse(arguments); err != nil || set.NArg() != 0 {
		return errors.New("RELEASE_INVALID: verify flags are incomplete")
	}
	result, err := privaterelease.Verify(ctx, options)
	if err != nil {
		return err
	}
	return writeJSON(stdout, result)
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
