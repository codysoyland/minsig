package sign

import (
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
)

// Result contains the results of a signing operation
type Result struct {
	BundlePath     string
	Bundle         *protobundle.Bundle
	PublicKeyPEM   string
	KeyAlgorithm   string
}