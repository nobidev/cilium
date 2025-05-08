---
name: Release a new version of Enterprise Hubble CLI vX.Y.Z-cee.1
about: Release a new version of Enterprise Hubble CLI vX.Y.Z-cee.1
title: 'Enterprise Hubble CLI vX.Y.Z-cee.1 release'
labels: kind/release
assignees: ''

---

## Prepare a Hubble CLI release

> [!IMPORTANT]
> When a new Cilium Enterprise release tag gets pushed, [Hubble CLI release workflow] gets triggered.
> Hubble CLI gets released only from the latest stable branch. For example, if the current supported
> versions are v1.15-ce, and v1.16-ce, Hubble CLI gets released from v1.16-ce branch. Ignore
> workflow runs from v1.15-ce branches.

- [ ] Ask [Hubble team] to approve the [Hubble CLI release workflow] run.
- [ ] Wait for the workflow to finish. A draft release gets pushed to [isovalent/hubble-releases repo].
- [ ] Set environment variables for previous and new releases. For example:

      export CEE_PREVIOUS_RELEASE=v1.16.4-cee.1
      export CEE_NEW_RELEASE=v1.16.5-cee.1

- [ ] Generate release notes:

      docker pull quay.io/cilium/release-tool:main
      alias release='docker run -it --rm -e GITHUB_TOKEN=$(gh auth token) quay.io/cilium/release-tool:main'
      GITHUB_TOKEN=$(gh auth token) release changelog \
        --base $CEE_PREVIOUS_RELEASE \
        --head $CEE_NEW_RELEASE \
        --repo isovalent/cilium \
        --label-filter hubble-cli

- [ ] Update the draft release with the generated release notes and publish the release.
- [ ] Add release notes in [isovalent/cilium-enterprise-docs repo].
      Use [this pull request](https://github.com/isovalent/cilium-enterprise-docs/pull/2294)
      as a reference.

[Hubble CLI release workflow]: https://github.com/isovalent/cilium/actions/workflows/release-hubble-cli.yaml
[Hubble team]: https://github.com/orgs/isovalent/teams/hubble
[isovalent/hubble-releases repo]: https://github.com/isovalent/hubble-releases/releases
[isovalent/cilium-enterprise-docs repo]: https://github.com/isovalent/cilium-enterprise-docs
