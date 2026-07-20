package release

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

type AcceptanceCase struct {
	Name                 string `json:"name"`
	Status               string `json:"status"`
	Code                 string `json:"code"`
	DurationMilliseconds int64  `json:"duration_ms"`
}

type AcceptanceEvidence struct {
	SchemaVersion int              `json:"schema_version"`
	Project       string           `json:"project"`
	Profile       string           `json:"profile"`
	Complete      bool             `json:"complete"`
	Cases         []AcceptanceCase `json:"cases"`
}

type acceptanceCommand struct {
	name, executable string
	arguments        []string
}

const sourceAcceptanceCommandTimeout = 30 * time.Minute

var sourceAcceptanceCommands = []acceptanceCommand{
	{"packaging-go-test", "go", []string{"test", "-p=1", "./internal/systeminstall", "./internal/cli", "./cmd/private-vm", "./cmd/private-vm-bundle-manifest"}},
	{"packaging-go-vet", "go", []string{"vet", "-p=1", "./internal/systeminstall", "./internal/cli", "./cmd/private-vm", "./cmd/private-vm-bundle-manifest"}},
	{"release-go-test", "go", []string{"test", "-p=1", "./internal/release", "./cmd/private-vm-release", "./cmd/private-vm-release-acceptance"}},
	{"release-go-vet", "go", []string{"vet", "-p=1", "./internal/release", "./cmd/private-vm-release", "./cmd/private-vm-release-acceptance"}},
	{"packaging-policy", "python3", []string{"tools/check_packaging_assets.py"}},
	{"schema-validation", "python3", []string{"tools/validate_schemas.py"}},
	{"example-validation", "python3", []string{"tools/validate_examples.py"}},
	{"workflow-policy-tests", "python3", []string{"tools/test_workflow_policy.py"}},
	{"workflow-policy", "python3", []string{"tools/check_workflow_policy.py"}},
}

var unavailableLiveGates = []string{"protected-release-environment", "package-publication", "anonymous-clean-room", "distribution-vm-install"}

type acceptanceExecutor interface {
	Run(context.Context, string, []string, []string) error
}
type execAcceptance struct{ directory string }

func (runner execAcceptance) Run(ctx context.Context, executable string, arguments, environment []string) error {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Dir = runner.directory
	command.Env = environment
	command.Stdout = nil
	command.Stderr = nil
	return command.Run()
}

// RunSourceAcceptance runs only the fixed lightweight source checks. Live-only
// gates are emitted as blocking, so source success can never be mistaken for a
// complete release acceptance result.
func RunSourceAcceptance(ctx context.Context, workDir, jsonPath, junitPath string) error {
	return runSourceAcceptance(ctx, workDir, jsonPath, junitPath, execAcceptance{directory: workDir})
}

func runSourceAcceptance(ctx context.Context, workDir, jsonPath, junitPath string, runner acceptanceExecutor) error {
	if !filepath.IsAbs(workDir) || filepath.Clean(workDir) != workDir || workDir == "/" || !safeEvidencePath(jsonPath) || !safeEvidencePath(junitPath) || runner == nil {
		return releaseError(CodeInvalid, "The acceptance evidence request is unsafe.", "Use exact new JSON and JUnit paths outside the source tree root.", nil)
	}
	evidence := AcceptanceEvidence{SchemaVersion: SchemaVersion, Project: "private-vm", Profile: "source-only", Cases: make([]AcceptanceCase, 0, len(sourceAcceptanceCommands)+len(unavailableLiveGates))}
	environment := []string{"PATH=" + os.Getenv("PATH"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC", "CGO_ENABLED=0", "GOMAXPROCS=2", "GOMEMLIMIT=1536MiB", "NIX_CONFIG=max-jobs = 1\ncores = 2"}
	if home := os.Getenv("HOME"); home != "" {
		environment = append(environment, "HOME="+home)
	}
	if temporary := os.Getenv("TMPDIR"); temporary != "" {
		environment = append(environment, "TMPDIR="+temporary)
	}
	var gateErr error
	for _, command := range sourceAcceptanceCommands {
		start := time.Now()
		commandCtx, commandCancel := context.WithTimeout(ctx, sourceAcceptanceCommandTimeout)
		err := runner.Run(commandCtx, command.executable, command.arguments, environment)
		commandContextErr := commandCtx.Err()
		commandCancel()
		status, code := "passed", "OK"
		if err != nil {
			status = "failed"
			code = "SOURCE_GATE_FAILED"
			gateErr = err
		}
		if errors.Is(commandContextErr, context.DeadlineExceeded) {
			status = "failed"
			code = CodeTimeout
			gateErr = context.DeadlineExceeded
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			status = "failed"
			code = CodeCancelled
			gateErr = context.Canceled
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = "failed"
			code = CodeTimeout
			gateErr = context.DeadlineExceeded
		}
		evidence.Cases = append(evidence.Cases, AcceptanceCase{Name: command.name, Status: status, Code: code, DurationMilliseconds: max(time.Since(start).Milliseconds(), 0)})
		if gateErr != nil {
			break
		}
	}
	for _, name := range unavailableLiveGates {
		evidence.Cases = append(evidence.Cases, AcceptanceCase{Name: name, Status: "blocked", Code: "LIVE_GATE_UNAVAILABLE"})
	}
	if err := writeAcceptanceEvidence(jsonPath, junitPath, evidence); err != nil {
		return releaseError(CodeCleanupIncomplete, "Acceptance evidence could not be written atomically.", "Use new owner-controlled evidence paths and retry.", err)
	}
	if gateErr != nil {
		return contextReleaseError(ctx, releaseError(CodeGatesIncomplete, "A source acceptance command failed; remaining gates are blocking.", "Fix the first failed fixed command and rerun from the beginning.", gateErr))
	}
	return releaseError(CodeGatesIncomplete, "Source gates passed, but live release gates are unavailable and remain blocking.", "Run protected publication, anonymous verification and clean distribution acceptance before release.", nil)
}

func safeEvidencePath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

func writeAcceptanceEvidence(jsonPath, junitPath string, evidence AcceptanceEvidence) error {
	jsonBytes, err := json.Marshal(evidence)
	if err != nil {
		return err
	}
	jsonBytes = append(jsonBytes, '\n')
	type failure struct {
		Message string `xml:"message,attr"`
	}
	type testCase struct {
		Name    string   `xml:"name,attr"`
		Time    string   `xml:"time,attr"`
		Failure *failure `xml:"failure,omitempty"`
		Skipped *failure `xml:"skipped,omitempty"`
	}
	type suite struct {
		XMLName  xml.Name   `xml:"testsuite"`
		Name     string     `xml:"name,attr"`
		Tests    int        `xml:"tests,attr"`
		Failures int        `xml:"failures,attr"`
		Skipped  int        `xml:"skipped,attr"`
		Cases    []testCase `xml:"testcase"`
	}
	result := suite{Name: "private-vm-release-source", Tests: len(evidence.Cases)}
	for _, item := range evidence.Cases {
		test := testCase{Name: item.Name, Time: strconv.FormatFloat(float64(item.DurationMilliseconds)/1000, 'f', 3, 64)}
		if item.Status == "failed" {
			test.Failure = &failure{Message: item.Code}
			result.Failures++
		}
		if item.Status == "blocked" {
			test.Skipped = &failure{Message: item.Code}
			result.Skipped++
		}
		result.Cases = append(result.Cases, test)
	}
	xmlBytes, err := xml.Marshal(result)
	if err != nil {
		return err
	}
	xmlBytes = append([]byte(xml.Header), xmlBytes...)
	xmlBytes = append(xmlBytes, '\n')
	if err := writeNewAtomic(jsonPath, jsonBytes); err != nil {
		return err
	}
	if err := writeNewAtomic(junitPath, xmlBytes); err != nil {
		_ = os.Remove(jsonPath)
		return err
	}
	return nil
}

func writeNewAtomic(path string, data []byte) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("evidence destination already exists")
	}
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".private-vm-evidence-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	ok := false
	defer func() {
		_ = temporary.Close()
		if !ok {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryName, path); err != nil {
		return err
	}
	if err := os.Remove(temporaryName); err != nil {
		_ = os.Remove(path)
		return err
	}
	ok = true
	return syncDirectory(parent)
}
