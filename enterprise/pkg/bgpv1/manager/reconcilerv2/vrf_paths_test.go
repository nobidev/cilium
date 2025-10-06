// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package reconcilerv2

import (
	"github.com/stretchr/testify/require"

	bgptypes "github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type afSimplePathsMap map[bgptypes.Family][]string // list of nlris
type resourceAFSimplePathsMap map[resource.Key]afSimplePathsMap
type vrfSimplePathsMap map[string]resourceAFSimplePathsMap // vrf -> resource -> af -> simplePath

func compareSimplePath(req *require.Assertions, vrfSimplePath vrfSimplePathsMap, vrfPaths VRFPaths) {
	req.Len(vrfPaths, len(vrfSimplePath))

	for vrf, svcAFSimplePaths := range vrfSimplePath {
		svcAFPaths, exists := vrfPaths[vrf]
		req.True(exists, "expected vrf %s not found in vrfPaths %+v", vrf, vrfPaths)
		req.Len(svcAFPaths, len(svcAFSimplePaths))

		for svc, simpleSvcPaths := range svcAFSimplePaths {
			afPaths, exists := svcAFPaths[svc]
			req.True(exists, "expected svc %s not found in svcAFPaths %+v", svc, svcAFPaths)
			req.Len(afPaths, len(simpleSvcPaths))

			for af, simplePaths := range simpleSvcPaths {
				paths, exists := afPaths[af]
				req.True(exists, "expected af %s not found in afPaths %+v", af, afPaths)
				req.Len(paths, len(simplePaths))

				for _, path := range paths {
					found := false
					for _, nlri := range simplePaths {
						if nlri == path.NLRI.String() {
							found = true
						}
					}
					req.True(found, "expected path %s not found in paths %+v", path, simplePaths)
				}
			}
		}
	}
}
