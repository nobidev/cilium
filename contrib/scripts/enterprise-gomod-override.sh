#!/usr/bin/env bash

set -euo pipefail

# Generate go.mod with enterprise-specific overrides
make gomod-override

# Ensure new files are also considered in the diff
git add --intent-to-add .

# Check for diff
diff="$(git diff)"

if [ -n "$diff" ]; then
	echo "Mismatching go.mod:"
	echo "$diff"
	echo "Please run 'make gomod-override && go mod tidy && go mod vendor' and submit your changes"
	exit 1
fi

exit 0
