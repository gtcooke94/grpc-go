package spiffe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

type partialParsedSpiffeBundleMap struct {
	Bundles map[string]json.RawMessage `json:"trust_domains"`
}

// Loads a SPIFFE Bundle Map from a file. See the SPIFFE Bundle Map spec for
// more detail -
// https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Trust_Domain_and_Bundle.md#4-spiffe-bundle-format
//
// This API is experimental.
func LoadSpiffeBundleMap(filePath string) (map[string]*spiffebundle.Bundle, error) {
	bundleMapFile, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open spiffe bundle map file: %v", err)
	}
	defer bundleMapFile.Close()
	byteValue, _ := io.ReadAll(bundleMapFile)
	var result partialParsedSpiffeBundleMap
	err = json.Unmarshal([]byte(byteValue), &result)
	if err != nil {
		return nil, err
	}
	if result.Bundles == nil {
		return nil, errors.New("no content in spiffe bundle map file")
	}
	bundleMap := map[string]*spiffebundle.Bundle{}
	for trustDomain, jsonBundle := range result.Bundles {
		bundle, err := spiffebundle.Parse(spiffeid.RequireTrustDomainFromString(trustDomain), jsonBundle)
		if err != nil {
			return nil, fmt.Errorf("failed to parse bundle in map: %v", err)
		}
		bundleMap[trustDomain] = bundle
	}
	return bundleMap, nil
}
