# Hof's pinned Ansible Execution Environment - the one thing hofctl
# apply ever runs on the target through (see ADR 0004: "Signed
# Execution Environment, not local Ansible"). A plain, hand-written
# Dockerfile rather than ansible-builder's own generated one - simpler
# to read, review, and build locally with the exact same `docker build`
# every other Hof image already uses, and it's the review surface that
# actually matters here, not the tool that produced it.
#
# Digest-pinned base, matching every other image this platform builds
# and every other Hof-ops dependency (see the ssh-acceptance fixture's
# own Dockerfile comment on how a pin like this is obtained):
# `docker inspect --format '{{index .RepoDigests 0}}' python:3.13-slim-bookworm`
# after a fresh pull.
FROM python:3.13-slim-bookworm@sha256:c45a22ea000adfd9cda29364bbe7edd23001ce5cc2ad15857cfbf7766943b9ca

# Ansible itself, plus the Python bindings community.docker's own
# modules need to talk to Docker over its socket (docker>=7, the
# maintained "docker" package - "docker-py" is its old, unmaintained
# name) and community.crypto's TLS/certificate-handling modules need
# (cryptography). No compiler toolchain required - all three publish
# manylinux wheels for this base image's own platform/Python version.
RUN pip install --no-cache-dir \
  ansible-core==2.17.* \
  docker==7.* \
  cryptography==43.*

# Cosign - the image role's own image.verify action runs its real
# signature check from inside this container (never on the target;
# `cosign verify` only ever needs network access to the image's own
# registry and Sigstore's Fulcio/Rekor infrastructure, nothing
# target-side), the same real invocation shape scripts/build-release-
# lock.mjs's own verifySupplyChain already uses. Pinned exact version,
# checksum-verified against cosign's own published checksums file (see
# https://github.com/sigstore/cosign/releases/tag/v3.1.3) - the same
# digest-pinning discipline every other artifact this platform pulls in
# already follows.
ADD --checksum=sha256:4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71 \
  https://github.com/sigstore/cosign/releases/download/v3.1.3/cosign-linux-amd64 /usr/local/bin/cosign
RUN chmod +x /usr/local/bin/cosign

# Collections are pinned in requirements.yml (real versions, resolved
# and locked the same way `pnpm install --frozen-lockfile` locks a
# Node dependency tree) - never floated to "whatever's latest" at
# image-build time.
COPY requirements.yml /ansible/requirements.yml
RUN ansible-galaxy collection install -r /ansible/requirements.yml -p /usr/share/ansible/collections

# The roles themselves are baked into the image - "pinned Execution
# Environment" means the whole deployment logic is signed and
# immutable, not just the Ansible runtime underneath it. hofctl apply
# never mounts a live roles/ directory from the operator's own
# workstation into a container at apply time; whatever this specific,
# signed image digest contains is what runs, full stop.
COPY ansible.cfg /ansible/ansible.cfg
COPY playbook.yml /ansible/playbook.yml
COPY roles /ansible/roles

ENV ANSIBLE_CONFIG=/ansible/ansible.cfg
WORKDIR /ansible

# No ENTRYPOINT/CMD that runs anything on its own - hofctl apply invokes
# `ansible-playbook /ansible/playbook.yml` (see scripts/apply.mjs)
# inside a container from this image explicitly, once per operation,
# never as a long-running daemon.
