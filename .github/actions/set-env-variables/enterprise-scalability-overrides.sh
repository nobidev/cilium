#!/usr/bin/env bash

echo "GCP_PERF_RESULTS_BUCKET=gs://cilium-scale-results-cee" >> "$GITHUB_ENV"
# Memory usage is higher for CEE as we have a slightly bigger binary
echo "CL2_MEDIAN_MEM_USAGE_THRESHOLD=270" >> "$GITHUB_ENV"
# Create an enterprise EGW policy, rather than the OSS one.
# Additionally tune the CPU/memory thresholds, considering that more work needs
# to be done to process enterprise policies, and that the Cilium binary is larger.
echo "CL2_EGW_POLICY_TEMPLATE=manifests/enterprise-egw-policy.yaml" >> "$GITHUB_ENV"
echo "CL2_EGW_MASQ_CPU_USAGE_THRESHOLD=0.17" >> "$GITHUB_ENV"
echo "CL2_EGW_MASQ_MEM_USAGE_THRESHOLD=320" >> "$GITHUB_ENV"
echo "EGRESS_GATEWAY_SCALE_HELM_VALUES=--helm-set=healthChecking=false --helm-set=endpointHealthChecking.enabled=false \
    --helm-set=enterprise.healthServerWithoutActiveChecks.enabled=true" >> "$GITHUB_ENV"
