#!/usr/bin/env bash

set -euo pipefail

# Remove generated generated code
find enterprise/api/extensions -name '*.go' -delete
find enterprise/fqdn-proxy/api/v1/dnsproxy -name '*.go' -delete
find enterprise/pkg/hubble/aggregation/api/aggregation -name '*.go' -delete
find enterprise/pkg/privnet/health/grpc/api/v1 -name '*.go' -delete

# Regenerate all API-related files.
make generate-enterprise-apis

# Ensure new files are also considered in the diff
git add --intent-to-add .

# Check for diff
diff="$(git diff)"

if [ -n "$diff" ]; then
	echo "Mismatching enterprise API source code:"
	echo "$diff"
	echo "Please run 'make generate-enterprise-apis' and submit your changes"
	exit 1
fi

exit 0
