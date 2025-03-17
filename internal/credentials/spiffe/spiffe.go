/*
 *
 * Copyright 2025 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package spiffe defines APIs for working with SPIFFE Bundle Maps.
//
// All APIs in this package are experimental.
package spiffe

import (
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// BundleMap represents a SPIFFE Bundle Map per the spec
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format.
type BundleMap map[string]*spiffebundle.Bundle

type partialParsedSPIFFEBundleMap struct {
	Bundles map[string]json.RawMessage `json:"trust_domains"`
}

// BundleMapFromBytes parses bytes into a SPIFFE Bundle Map. See the
// SPIFFE Bundle Map spec for more detail -
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format
// If duplicate keys are encountered in the JSON parsing, Go's default unmarshal
// behavior occurs which causes the last processed entry to be the entry in the
// parsed map.
func BundleMapFromBytes(bundleMapBytes []byte) (map[string]*spiffebundle.Bundle, error) {
	var result partialParsedSPIFFEBundleMap
	if err := json.Unmarshal(bundleMapBytes, &result); err != nil {
		return nil, err
	}
	if result.Bundles == nil {
		return nil, fmt.Errorf("spiffe: BundleMapFromBytes() no bundles parsed from spiffe bundle map bytes")
	}
	bundleMap := map[string]*spiffebundle.Bundle{}
	for td, jsonBundle := range result.Bundles {
		trustDomain, err := spiffeid.TrustDomainFromString(td)
		if err != nil {
			return nil, fmt.Errorf("spiffe: BundleMapFromBytes() invalid trust domain %q found when parsing SPIFFE Bundle Map: %v", td, err)
		}
		bundle, err := spiffebundle.Parse(trustDomain, jsonBundle)
		if err != nil {
			return nil, fmt.Errorf("spiffe: BundleMapFromBytes() failed to parse bundle for trust domain %q: %v", td, err)
		}
		bundleMap[td] = bundle
	}
	return bundleMap, nil
}

// GetRootsFromSPIFFEBundleMap returns the root trust certificates from the
// SPIFFE bundle map for the given trust domain from the leaf certificate.
func GetRootsFromSPIFFEBundleMap(bundleMap BundleMap, leafCert *x509.Certificate) (*x509.CertPool, error) {
	// 1. Upon receiving a peer certificate, verify that it is a well-formed SPIFFE
	//    leaf certificate.  In particular, it must have a single URI SAN containing
	//    a well-formed SPIFFE ID ([SPIFFE ID format]).
	// spiffeID := credinternal.SPIFFEIDFromCert(leafCert)
	spiffeID, err := IDFromCert(leafCert)
	if err != nil {
		return nil, fmt.Errorf("spiffe: could not get spiffe ID from peer leaf cert but verification with spiffe trust map was configured: %v", err)
	}

	// 2. Use the trust domain in the peer certificate's SPIFFE ID to lookup
	//    the SPIFFE trust bundle. If the trust domain is not contained in the
	//    configured trust map, reject the certificate.
	spiffeBundle, ok := bundleMap[spiffeID.TrustDomain().Name()]
	if !ok {
		return nil, fmt.Errorf("spiffe: no bundle found for peer certificates trust domain %v but verification with a SPIFFE trust map was configured", spiffeID.TrustDomain().Name())
	}
	roots := spiffeBundle.X509Authorities()
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}
	return rootPool, nil
}

// IDFromCert parses the SPIFFE ID from x509.Certificate. If the SPIFFE
// ID format is invalid, return nil with warning.
func IDFromCert(cert *x509.Certificate) (*spiffeid.ID, error) {
	// return spiffeid.FromURI(cert.URIs)
	if cert == nil {
		return nil, fmt.Errorf("spiffe: IDFromCert() failed because input cert is nil")
	}
	// A valid SPIFFE Certificate should have exactly one URI
	if cert.URIs == nil {
		return nil, fmt.Errorf("spiffe: IDFromCert() failed because input cert has no URIs")
	}
	if len(cert.URIs) > 1 {
		return nil, fmt.Errorf("spiffe: IDFromCert() failed because input cert has more than 1 URI")
	}
	ID, err := spiffeid.FromURI(cert.URIs[0])
	if err != nil {
		return nil, fmt.Errorf("spiffe: IDFromCert() failed with invalid spiffeid: %v", err)
	}
	return &ID, nil
}
