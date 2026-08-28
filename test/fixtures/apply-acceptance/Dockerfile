# Ephemeral SSH server for real hofctl apply acceptance testing
# (test/apply-acceptance.mjs, run via `pnpm test:apply-ssh`) - a sibling
# of ../ssh-acceptance's own fixture, with real differences: hofprobe
# has a genuine passwordless sudoers entry here (hofctl preflight's own
# checkSudo already requires this on any real target apply would ever
# run against, so ../ssh-acceptance's fixture deliberately does NOT have
# it - its own tests exercise the "no sudo at all" unreadable-state path
# instead), and this container runs real systemd as PID 1 - the host
# role's own real implementation (item 8, PR #28) manages Docker via
# `ansible.builtin.systemd`, exactly like it would on a real Debian/
# Ubuntu server (which always runs systemd as init); a plain
# single-process container has no init system to manage services
# through at all, so this is a real, necessary difference from
# ../ssh-acceptance's fixture, not an arbitrary one. See
# test/apply-acceptance.mjs's own `docker run` for the (deliberately
# non-privileged, non-host-cgroup-namespace-sharing) flags this needs
# to actually boot systemd inside a container.
#
# Same digest-pinned Debian 12 base as ../ssh-acceptance (see that
# Dockerfile's own comment on how the pin is obtained).
FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssh-server sudo ca-certificates systemd systemd-sysv \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /run/sshd \
  && useradd -m -s /bin/sh hofprobe \
  && echo 'hofprobe ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/hofprobe \
  && chmod 440 /etc/sudoers.d/hofprobe \
  && systemctl enable ssh

RUN { \
  echo 'Port 22'; \
  echo 'PasswordAuthentication no'; \
  echo 'KbdInteractiveAuthentication no'; \
  echo 'PubkeyAuthentication yes'; \
  echo 'PermitRootLogin no'; \
  } > /etc/ssh/sshd_config.d/hof-probe.conf

COPY entrypoint.sh /usr/local/bin/hof-probe-entrypoint.sh
RUN chmod +x /usr/local/bin/hof-probe-entrypoint.sh

# The standard signal every systemd-in-Docker image sets - without it,
# systemd doesn't reliably detect it's running inside a container and
# can behave unpredictably (including, in practice, never actually
# logging its own boot sequence to stdout/stderr the way `docker logs`
# can see - a real, confirmed symptom hit during this fixture's own
# development, not a hypothetical one).
ENV container=docker

EXPOSE 22
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/local/bin/hof-probe-entrypoint.sh"]
