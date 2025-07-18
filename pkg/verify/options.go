package verify

import (
	"github.com/sigstore/sigstore-go/pkg/root"
)

// Options contains all parameters for verification operations
type Options struct {
	// Content options
	ArtifactPath  string
	BundlePath    string
	IsAttestation bool
	IsOCI         bool
	
	// Public key verification
	PublicKeyPath string
	
	// Certificate verification
	CertificateIdentity      string
	CertificateIdentityRegex string
	CertificateIssuer        string
	CertificateIssuerRegex   string
	
	// Requirements (inverted logic)
	IgnoreSCT             bool
	IgnoreTimestamp       bool
	IgnoreTransparencyLog bool
	
	// Configuration (provided by caller, not fetched internally)
	TrustedRoot *root.TrustedRoot
}