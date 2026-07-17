#!/usr/bin/env bash
#
# Capture forensic data about the EKS worker nodes and their backing EC2
# instances after a test failure. Every probe is best-effort: we deliberately do
# NOT set -e, so a single failing command (e.g. the node is already gone) never
# aborts the rest of the collection. The point is to answer, for the next
# occurrence, "who terminated these instances?" without having to guess.

set -u -o pipefail

ARTIFACTS_SUFFIX="${1:?artifacts_suffix argument is required}"

OUTDIR="$(mktemp -d)"
echo "Collecting EKS node forensics into ${OUTDIR}"

# Kubernetes view: which nodes still exist, and the recent events (cordon,
# NotReady, DeletingNode "because it does not exist in the cloud provider", ...).
kubectl get nodes -o wide > "${OUTDIR}/nodes.txt" 2>&1
kubectl get nodes -o json > "${OUTDIR}/nodes.json" 2>&1
kubectl get events -A --sort-by=.lastTimestamp > "${OUTDIR}/events.txt" 2>&1

# Map every node to its backing EC2 instance via the providerID
# (aws:///<az>/<instance-id>) and interrogate AWS about each instance.
PROVIDER_IDS=$(kubectl get nodes -o jsonpath='{range .items[*]}{.spec.providerID}{"\n"}{end}' 2>/dev/null)

if [ -z "${PROVIDER_IDS}" ]; then
  echo "No node providerIDs found (all nodes may already be gone)." | tee "${OUTDIR}/no-nodes.txt"
fi

echo "${PROVIDER_IDS}" | while read -r provider_id; do
  [ -z "${provider_id}" ] && continue

  # providerID looks like aws:///us-west-2b/i-0123456789abcdef0
  instance_id="${provider_id##*/}"
  case "${instance_id}" in
    i-*) ;;
    *)
      echo "Skipping unexpected providerID: ${provider_id}"
      continue
      ;;
  esac

  echo "=== Forensics for instance ${instance_id} (${provider_id}) ==="

  # EC2 instance state and, most importantly, the state-transition reason which
  # for a fleet-wide event reads e.g. "Server.InsufficientInstanceCapacity" or a
  # user/service-initiated shutdown.
  aws ec2 describe-instances --instance-ids "${instance_id}" \
    --query 'Reservations[].Instances[].{state:State.Name,reason:StateTransitionReason,stateReason:StateReason}' \
    > "${OUTDIR}/ec2-describe-${instance_id}.json" 2>&1

  # ASG scaling activities mentioning this instance tell us whether the
  # Auto Scaling Group itself scaled the instance in.
  aws autoscaling describe-scaling-activities \
    --query "Activities[?contains(Description, '${instance_id}')]" \
    > "${OUTDIR}/asg-activities-${instance_id}.json" 2>&1

  # CloudTrail is the decisive probe: it names the principal behind the
  # TerminateInstances call, distinguishing an AWS-side region-scoped event from
  # our own pool-manager / eksctl teardown.
  aws cloudtrail lookup-events \
    --lookup-attributes "AttributeKey=ResourceName,AttributeValue=${instance_id}" \
    > "${OUTDIR}/cloudtrail-${instance_id}.json" 2>&1
done

TARBALL="eks-node-forensics-${ARTIFACTS_SUFFIX}.tar.gz"
tar -czf "${TARBALL}" -C "${OUTDIR}" .
echo "Wrote ${TARBALL}"
