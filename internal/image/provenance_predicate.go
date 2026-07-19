package image

import (
	"context"
	"regexp"
	"strings"
)

const (
	officialRepository        = "StevenBuglione/private-vm"
	officialRepositoryID      = "1305109560"
	officialRepositoryOwnerID = "34593055"
	officialWorkflow          = ".github/workflows/release.yml"
	officialOIDCIssuer        = "https://token.actions.githubusercontent.com"
	officialSubjectName       = "image.qcow2.zst"
	inTotoStatementV1         = "https://in-toto.io/Statement/v1"
	slsaProvenanceV1          = "https://slsa.dev/provenance/v1"
	githubWorkflowBuildType   = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
	githubHostedRunnerBuilder = "https://github.com/actions/runner/github-hosted"
)

var (
	decimalIdentifierPattern  = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	officialReleaseRefPattern = regexp.MustCompile(`^refs/tags/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.(0|[1-9][0-9]*))?$`)
)

type provenanceStatement struct {
	Type          string              `json:"_type"`
	Subject       []provenanceSubject `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     *githubPredicate    `json:"predicate"`
}

type provenanceSubject struct {
	Name   string            `json:"name"`
	Digest *provenanceDigest `json:"digest"`
}

type provenanceDigest struct {
	SHA256 string `json:"sha256"`
}

type githubPredicate struct {
	BuildDefinition *githubBuildDefinition `json:"buildDefinition"`
	RunDetails      *githubRunDetails      `json:"runDetails"`
}

type githubBuildDefinition struct {
	BuildType            string                     `json:"buildType"`
	ExternalParameters   *githubExternalParameters  `json:"externalParameters"`
	InternalParameters   *githubInternalParameters  `json:"internalParameters"`
	ResolvedDependencies []githubResolvedDependency `json:"resolvedDependencies"`
}

type githubExternalParameters struct {
	Workflow *githubWorkflowParameters `json:"workflow"`
}

type githubWorkflowParameters struct {
	Ref        string `json:"ref"`
	Repository string `json:"repository"`
	Path       string `json:"path"`
}

type githubInternalParameters struct {
	GitHub *githubInternalIdentity `json:"github"`
}

type githubInternalIdentity struct {
	EventName         string `json:"event_name"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwnerID string `json:"repository_owner_id"`
}

type githubResolvedDependency struct {
	URI    string               `json:"uri"`
	Digest *gitDependencyDigest `json:"digest"`
}

type gitDependencyDigest struct {
	GitCommit string `json:"gitCommit"`
}

type githubRunDetails struct {
	Builder  *githubBuilder  `json:"builder"`
	Metadata *githubMetadata `json:"metadata"`
}

type githubBuilder struct {
	ID string `json:"id"`
}

type githubMetadata struct {
	InvocationID string `json:"invocationId"`
}

var provenanceStatementFields = []string{"_type", "subject", "predicateType", "predicate"}

func decodeProvenanceStatement(data []byte, maximumDepth int) (provenanceStatement, error) {
	var statement provenanceStatement
	if err := decodeClosedJSON(data, maximumDepth, provenanceStatementFields, &statement); err != nil {
		return provenanceStatement{}, provenancePredicateError(
			"The signed provenance statement is not a closed SLSA v1 document.",
			err,
		)
	}
	return statement, nil
}

func (statement provenanceStatement) validate(ctx context.Context, manifest Manifest) error {
	if err := ctx.Err(); err != nil {
		return contextError(ctx, err)
	}
	if manifest.SourceRepository != officialRepository || manifest.Workflow != officialWorkflow ||
		!officialReleaseRefPattern.MatchString(manifest.SourceRef) {
		return provenanceIdentityError("The image manifest does not name the immutable official repository and release workflow.", nil)
	}
	if statement.Type != inTotoStatementV1 || statement.PredicateType != slsaProvenanceV1 ||
		len(statement.Subject) != 1 || statement.Subject[0].Name != officialSubjectName ||
		statement.Subject[0].Digest == nil || statement.Subject[0].Digest.SHA256 != strings.TrimPrefix(manifest.ImageDigest, "sha256:") ||
		statement.Predicate == nil || statement.Predicate.BuildDefinition == nil || statement.Predicate.RunDetails == nil {
		return provenancePredicateError("The signed statement identity or single compressed-image subject is invalid.", nil)
	}

	definition := statement.Predicate.BuildDefinition
	if definition.BuildType != githubWorkflowBuildType || definition.ExternalParameters == nil ||
		definition.ExternalParameters.Workflow == nil || definition.InternalParameters == nil ||
		definition.InternalParameters.GitHub == nil || len(definition.ResolvedDependencies) != 1 {
		return provenancePredicateError("The signed GitHub Actions build definition is missing or has an unsupported build type.", nil)
	}
	repositoryURL := "https://github.com/" + officialRepository
	workflow := definition.ExternalParameters.Workflow
	if workflow.Ref != manifest.SourceRef || workflow.Repository != repositoryURL || workflow.Path != "/"+officialWorkflow {
		return provenanceIdentityError("The signed workflow repository, path or ref does not match the official image manifest.", nil)
	}
	internal := definition.InternalParameters.GitHub
	if internal.EventName != "push" || internal.RepositoryID != officialRepositoryID ||
		internal.RepositoryOwnerID != officialRepositoryOwnerID {
		return provenancePredicateError("The signed GitHub invocation identity is not a bounded protected push event.", nil)
	}
	dependency := definition.ResolvedDependencies[0]
	if dependency.URI != "git+"+repositoryURL+"@"+manifest.SourceRef || dependency.Digest == nil ||
		dependency.Digest.GitCommit != manifest.SourceCommit {
		return provenanceIdentityError("The signed source dependency does not match the official repository ref and commit.", nil)
	}

	run := statement.Predicate.RunDetails
	if run.Builder == nil || run.Builder.ID != githubHostedRunnerBuilder || run.Metadata == nil ||
		!validRunInvocation(run.Metadata.InvocationID) {
		return provenancePredicateError("The signed GitHub-hosted runner identity or invocation is invalid.", nil)
	}
	return nil
}

// invocationIDForPolicy reads only the minimum untrusted payload field needed
// to construct the exact certificate-extension policy. The complete statement
// is validated only after Sigstore has authenticated this payload.
func (statement provenanceStatement) invocationIDForPolicy() (string, error) {
	if statement.Predicate == nil || statement.Predicate.RunDetails == nil ||
		statement.Predicate.RunDetails.Metadata == nil ||
		!validRunInvocation(statement.Predicate.RunDetails.Metadata.InvocationID) {
		return "", provenancePredicateError("The signed GitHub run invocation is missing or invalid.", nil)
	}
	return statement.Predicate.RunDetails.Metadata.InvocationID, nil
}

func officialWorkflowIdentity(manifest Manifest) string {
	return "https://github.com/" + officialRepository + "/" + officialWorkflow + "@" + manifest.SourceRef
}

func validRunInvocation(value string) bool {
	prefix := "https://github.com/" + officialRepository + "/actions/runs/"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, prefix), "/")
	return len(parts) == 3 && decimalIdentifierPattern.MatchString(parts[0]) &&
		parts[1] == "attempts" && decimalIdentifierPattern.MatchString(parts[2])
}

func provenancePredicateError(message string, cause error) error {
	return imageError(
		CodeProvenancePredicate,
		message,
		"Use the official protected release workflow to produce one exact SLSA v1 statement for the compressed QCOW2 layer.",
		cause,
	)
}

func provenanceIdentityError(message string, cause error) error {
	return imageError(
		CodeProvenanceIdentity,
		message,
		"Do not use the artifact; pull an image attested by the exact official repository, workflow, ref and source commit.",
		cause,
	)
}
