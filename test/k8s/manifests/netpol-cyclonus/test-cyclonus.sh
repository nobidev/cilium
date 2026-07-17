#!/usr/bin/env bash

set -eo pipefail
set -xv

# set up cyclonus
kubectl create clusterrolebinding cyclonus --clusterrole=cluster-admin --serviceaccount=kube-system:cyclonus
kubectl create sa cyclonus -n kube-system
kubectl create -f ./install-cyclonus.yml

# don't fail on errors, so we can dump the logs.
set +e

time kubectl wait --for=condition=complete --timeout=60m -n kube-system job.batch/cyclonus
rc=$?

# Dump the logs of every pod that ever backed the job, current and previous
# containers alike. A single "kubectl logs job.batch/cyclonus" only resolves to
# one pod, so when the original runner crashes and the Job controller starts a
# replacement, the crashed pod's output (e.g. a Go panic stack) is lost. Iterate
# explicitly so a crash is always diagnosable.
for pod in $(kubectl get pods -n kube-system -l job-name=cyclonus -o jsonpath='{.items[*].metadata.name}'); do
    echo "===== logs for pod $pod ====="
    kubectl logs -n kube-system "$pod" || true
    echo "===== previous-container logs for pod $pod (if any) ====="
    kubectl logs -n kube-system "$pod" --previous 2>/dev/null || true
done

# grab the job logs used for the pass/fail check below
LOG_FILE=$(mktemp)
kubectl logs -n kube-system job.batch/cyclonus > "$LOG_FILE"
cat "$LOG_FILE"

# retrieve the JUnit results file from the pod
RESULTS_DIR="cyclonus-results"
mkdir -p "$RESULTS_DIR"

# Get the pod name for the completed job
POD_NAME=$(kubectl get pods -n kube-system -l job-name=cyclonus -o jsonpath='{.items[0].metadata.name}')

if [ -n "$POD_NAME" ]; then
    echo "Retrieving JUnit results from pod: $POD_NAME"
    kubectl cp -n kube-system "$POD_NAME":/results/cyclonus-results.xml "$RESULTS_DIR/cyclonus-results.xml" || echo "Failed to copy JUnit results file"

    # Check if the file was successfully copied and display its contents
    if [ -f "$RESULTS_DIR/cyclonus-results.xml" ]; then
        echo "JUnit results file retrieved successfully:"
        ls -la "$RESULTS_DIR/cyclonus-results.xml"
        echo "Contents preview:"
        head -20 "$RESULTS_DIR/cyclonus-results.xml"
    else
        echo "Warning: JUnit results file not found or could not be retrieved"
    fi
else
    echo "Warning: Could not find cyclonus pod to retrieve results"
fi

# if 'failure' is in the logs, fail; otherwise succeed
cat "$LOG_FILE" | grep "failure" > /dev/null 2>&1 && rc=1
exit $rc
