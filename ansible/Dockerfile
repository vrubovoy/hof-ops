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
COPY roles /ansible/roles

ENV ANSIBLE_CONFIG=/ansible/ansible.cfg
WORKDIR /ansible

# No ENTRYPOINT/CMD that runs anything on its own - hofctl apply invokes
# `ansible-playbook` (or an equivalent typed entry point, see PR #27)
# inside a container from this image explicitly, once per operation
# batch, never as a long-running daemon.
