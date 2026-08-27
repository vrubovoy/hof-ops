# Ephemeral SSH server for real hofctl apply acceptance testing
# (test/apply-acceptance.mjs, run via `pnpm test:apply-ssh`) - a sibling
# of ../ssh-acceptance's own fixture, with one real difference: hofprobe
# has a genuine passwordless sudoers entry here. hofctl preflight's own
# checkSudo already requires this on any real target apply would ever
# run against, so ../ssh-acceptance's fixture deliberately does NOT have
# it (its own tests exercise the "no sudo at all" unreadable-state path
# instead) - apply's own real target-mutate.mjs writes (the lock,
# journal, events) genuinely need it, so this fixture is kept separate
# rather than changing ../ssh-acceptance's own load-bearing assertions.
#
# Same digest-pinned Debian 12 base as ../ssh-acceptance (see that
# Dockerfile's own comment on how the pin is obtained).
FROM debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssh-server sudo ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /run/sshd \
  && useradd -m -s /bin/sh hofprobe \
  && echo 'hofprobe ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/hofprobe \
  && chmod 440 /etc/sudoers.d/hofprobe

RUN { \
  echo 'Port 22'; \
  echo 'PasswordAuthentication no'; \
  echo 'KbdInteractiveAuthentication no'; \
  echo 'PubkeyAuthentication yes'; \
  echo 'PermitRootLogin no'; \
  } > /etc/ssh/sshd_config.d/hof-probe.conf

COPY entrypoint.sh /usr/local/bin/hof-probe-entrypoint.sh
RUN chmod +x /usr/local/bin/hof-probe-entrypoint.sh

EXPOSE 22
CMD ["/usr/local/bin/hof-probe-entrypoint.sh"]
