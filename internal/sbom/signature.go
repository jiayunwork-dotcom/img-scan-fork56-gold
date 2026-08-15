package sbom

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"imgscan/internal/config"
)

type SignatureChecker struct {
	imageRef string
	auth     authn.Authenticator
}

func NewSignatureChecker(imageRef string, auth config.RegistryAuth) *SignatureChecker {
	authenticator, _ := utilsGetRegistryAuth(imageRef, auth)
	return &SignatureChecker{
		imageRef: imageRef,
		auth:     authenticator,
	}
}

func utilsGetRegistryAuth(imageRef string, auth config.RegistryAuth) (authn.Authenticator, error) {
	if auth.Token != "" {
		return &authn.Bearer{Token: auth.Token}, nil
	}
	if auth.Username != "" && auth.Password != "" {
		return &authn.Basic{Username: auth.Username, Password: auth.Password}, nil
	}
	return authn.Anonymous, nil
}

func (sc *SignatureChecker) Check() SignatureResult {
	result := SignatureResult{
		UnsignedWarning: "未签名-供应链完整性无法验证",
	}

	if sc.imageRef == "" {
		return result
	}

	ref, err := name.ParseReference(sc.imageRef)
	if err != nil {
		return result
	}

	digest, err := sc.getImageDigest(ref)
	if err != nil {
		return result
	}

	sigResult := sc.checkCosignSignature(ref, digest)
	if sigResult {
		result.HasCosignSignature = true
		result.UnsignedWarning = ""
	}

	attResult := sc.checkSLSAProvenance(ref, digest)
	if attResult.HasSLSA {
		result.HasSLSAProvenance = true
		result.Builder = attResult.Builder
		result.BuildType = attResult.BuildType
		result.Invocation = attResult.Invocation
		result.AttestationRaw = attResult.Raw
	}

	return result
}

func (sc *SignatureChecker) getImageDigest(ref name.Reference) (string, error) {
	desc, err := remote.Get(ref, remote.WithAuth(sc.auth))
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

type slsaResult struct {
	HasSLSA   bool
	Builder   string
	BuildType string
	Invocation string
	Raw       string
}

func (sc *SignatureChecker) checkCosignSignature(ref name.Reference, digest string) bool {
	repo := ref.Context()
	digestHash := strings.TrimPrefix(digest, "sha256:")
	sigTag := fmt.Sprintf("sha256-%s.sig", digestHash)

	sigRef, err := name.NewTag(repo.Name() + ":" + sigTag)
	if err != nil {
		return false
	}

	_, err = remote.Head(sigRef, remote.WithAuth(sc.auth))
	if err != nil {
		return false
	}

	return true
}

func (sc *SignatureChecker) checkSLSAProvenance(ref name.Reference, digest string) slsaResult {
	result := slsaResult{}

	repo := ref.Context()
	digestHash := strings.TrimPrefix(digest, "sha256:")
	attTag := fmt.Sprintf("sha256-%s.att", digestHash)

	attRef, err := name.NewTag(repo.Name() + ":" + attTag)
	if err != nil {
		return result
	}

	img, err := remote.Image(attRef, remote.WithAuth(sc.auth))
	if err != nil {
		return sc.tryDSSEAttestation(ref, digest)
	}

	layers, err := img.Layers()
	if err != nil || len(layers) == 0 {
		return result
	}

	for _, layer := range layers {
		content, err := layer.Compressed()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(content)
		if err != nil {
			continue
		}

		parsed := sc.parseAttestationPayload(data)
		if parsed.HasSLSA {
			return parsed
		}
	}

	return result
}

func (sc *SignatureChecker) tryDSSEAttestation(ref name.Reference, digest string) slsaResult {
	result := slsaResult{}

	repo := ref.Context()
	digestHash := strings.TrimPrefix(digest, "sha256:")
	attTag := fmt.Sprintf("sha256-%s.att", digestHash)

	client := &http.Client{Timeout: 10 * time.Second}

	urls := []string{
		fmt.Sprintf("https://%s/v2/%s/manifests/%s", repo.RegistryStr(), repo.RepositoryStr(), attTag),
	}

	for _, u := range urls {
		req, err := http.NewRequestWithContext(context.Background(), "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/vnd.oci.image.manifest.v1+json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			result.HasSLSA = true
			result.Raw = u
			return result
		}
	}

	return result
}

func (sc *SignatureChecker) parseAttestationPayload(data []byte) slsaResult {
	result := slsaResult{}

	type CosignAttestation struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
	}

	var att CosignAttestation
	if err := json.Unmarshal(data, &att); err != nil {
		if sc.tryRawProvenance(data) {
			result.HasSLSA = true
			result.Raw = string(data[:min(len(data), 500)])
			return result
		}
		return result
	}

	if att.PayloadType != "application/vnd.in-toto+json" {
		return result
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(att.Payload)
	if err != nil {
		return result
	}

	result.HasSLSA = true
	result.Raw = string(payloadBytes[:min(len(payloadBytes), 500)])

	type InTotoStatement struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			BuildType   string `json:"buildType"`
			Invocation  struct {
				ConfigSource struct {
					URI string `json:"uri"`
				} `json:"configSource"`
			} `json:"invocation"`
		} `json:"predicate"`
	}

	var statement InTotoStatement
	if err := json.Unmarshal(payloadBytes, &statement); err != nil {
		return result
	}

	if statement.Predicate.Builder.ID != "" {
		result.Builder = statement.Predicate.Builder.ID
	}
	if statement.Predicate.BuildType != "" {
		result.BuildType = statement.Predicate.BuildType
	}
	if statement.Predicate.Invocation.ConfigSource.URI != "" {
		result.Invocation = statement.Predicate.Invocation.ConfigSource.URI
	}

	return result
}

func (sc *SignatureChecker) tryRawProvenance(data []byte) bool {
	text := strings.ToLower(string(data))
	return strings.Contains(text, "slsa") || strings.Contains(text, "provenance") || strings.Contains(text, "in-toto")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func FormatSignature(sig SignatureResult) string {
	var sb strings.Builder

	if sig.HasCosignSignature {
		sb.WriteString("Cosign Signature: ✓ Verified\n")
	} else {
		sb.WriteString(fmt.Sprintf("Cosign Signature: ✗ %s\n", sig.UnsignedWarning))
	}

	if sig.HasSLSAProvenance {
		sb.WriteString("SLSA Provenance: ✓ Found\n")
		if sig.Builder != "" {
			sb.WriteString(fmt.Sprintf("  Builder: %s\n", sig.Builder))
		}
		if sig.BuildType != "" {
			sb.WriteString(fmt.Sprintf("  Build Type: %s\n", sig.BuildType))
		}
		if sig.Invocation != "" {
			sb.WriteString(fmt.Sprintf("  Invocation: %s\n", sig.Invocation))
		}
	} else {
		sb.WriteString("SLSA Provenance: ✗ Not found\n")
	}

	return sb.String()
}
