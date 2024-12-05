#!/usr/bin/env bash

echo "GCP_PERF_RESULTS_BUCKET=gs://cilium-scale-results-cee" >> "$GITHUB_ENV"
# Memory usage is higher for CEE as we have a slightly bigger binary
echo "CL2_MEDIAN_MEM_USAGE_THRESHOLD=270" >> "$GITHUB_ENV"