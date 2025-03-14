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
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// BundleMap represents a SPIFFE Bundle Map per the spec
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format.
type BundleMap map[string]*spiffebundle.Bundle

type partialParsedSPIFFEBundleMap struct {
	Bundles map[string]json.RawMessage `json:"trust_domains"`
}

// LoadSPIFFEBundleMap loads a SPIFFE Bundle Map from a file. See the SPIFFE
// Bundle Map spec for more detail -
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format
// If duplicate keys are encountered in the JSON parsing, Go's default unmarshal
// behavior occurs which causes the last processed entry to be the entry in the
// parsed map.
func LoadSPIFFEBundleMap(filePath string) (BundleMap, error) {
	bundleMapRaw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return BundleMapFromBytes(bundleMapRaw)
}

// BundleMapFromBytes parses bytes into a SPIFFE Bundle Map. See the
// SPIFFE Bundle Map spec for more detail -
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format
// If duplicate keys are encountered in the JSON parsing, Go's default unmarshal
// behavior occurs which causes the last processed entry to be the entry in the
// parsed map.
func BundleMapFromBytes(bundleMapBytes []byte) (BundleMap, error) {
	var result partialParsedSPIFFEBundleMap
	err := json.Unmarshal(bundleMapBytes, &result)
	if err != nil {
		return nil, err
	}
	if result.Bundles == nil {
		return nil, fmt.Errorf("spiffe: BundleMapFromBytes() no bundles parsed from spiffe bundle map bytes")
	}
	bundleMap := map[string]*spiffebundle.Bundle{}
	for td, jsonBundle := range result.Bundles {
		trustDomain, err := spiffeid.TrustDomainFromString(td)
		if err != nil {
			return nil, fmt.Errorf("spiffe: BundleMapFromBytes() invalid trust domain (%v) found when parsing SPIFFE Bundle Map: %v", td, err)
		}
		bundle, err := spiffebundle.Parse(trustDomain, jsonBundle)
		if err != nil {
			return nil, fmt.Errorf("spiffe: BundleMapFromBytes() failed to parse bundle for trust domain %v: %v", td, err)
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
	// spiffeId := credinternal.SPIFFEIDFromCert(leafCert)
	spiffeId, err := IDFromCert(leafCert)
	if err != nil {
		return nil, err
	}

	// 2. Use the trust domain in the peer certificate's SPIFFE ID to lookup
	//    the SPIFFE trust bundle. If the trust domain is not contained in the
	//    configured trust map, reject the certificate.
	spiffeBundle, ok := bundleMap[spiffeId.TrustDomain().Name()]
	if !ok {
		return nil, fmt.Errorf("getRootsFromSPIFFEBundleMap() failed. No bundle found for peer certificates trust domain %v", spiffeId.TrustDomain().Name())
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
	if cert.URIs == nil {
		return nil, fmt.Errorf("spiffe: IDFromCert() failed because input cert has no URIs")
	}
	var spiffeID *spiffeid.ID
	for _, uri := range cert.URIs {
		if uri == nil || uri.Scheme != "spiffe" || uri.Opaque != "" || (uri.User != nil && uri.User.Username() != "") {
			continue
		}
		ID, err := spiffeid.FromURI(uri)
		if err != nil {
			return nil, fmt.Errorf("spiffe: IDFromCert() failed with invalid spiffeid: %v", err)
		}
		spiffeID = &ID
	}
	return spiffeID, nil
}
