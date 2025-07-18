package sign

import (
	"github.com/sigstore/sigstore-go/pkg/root"
)

// Options contains all parameters for signing operations
type Options struct {
	// Content options
	ArtifactPath    string
	AttestationPath string
	
	// Key options
	PrivateKeyPath  string  // If empty, ephemeral key will be used
	
	// Output options
	OutputPath    string
	AttachToImage bool
	
	// Service options
	SkipTSA     bool
	SkipRekor   bool
	IDToken     string
	
	// Configuration (provided by caller, not fetched internally)
	TrustedRoot   *root.TrustedRoot
	SigningConfig *root.SigningConfig
}