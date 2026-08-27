# Ephemeral SSH server for real transport acceptance testing
# (test/ssh-acceptance.test.mjs, run via `pnpm test:ssh`) - exercises
# target-inspector.mjs's actual OpenSSH handshake, both trust modes, and
# the real target-probe.sh, without ever touching a real production
# host. No baked keys, no secrets - host/user keypairs are generated
# fresh per test run and bind-mounted in.
#
# Pinned to Debian 12 - one of hofctl preflight's own two supported
# platforms, so `os`/`arch` checks exercise a real match, not a
# synthetic stand-in.
FROM debian:12-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssh-server sudo ca-certificates \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /run/sshd \
  && useradd -m -s /bin/sh hofprobe

# No Subsystem line here - Debian's own default sshd_config already
# defines "Subsystem sftp ..." once, and sshd refuses to start if a
# drop-in redefines it (confirmed by actually hitting that exact
# startup failure while building this fixture). sftp is never used by
# this test anyway.
RUN { \
  echo 'Port 22'; \
  echo 'PasswordAuthentication no'; \
  echo 'KbdInteractiveAuthentication no'; \
  echo 'PubkeyAuthentication yes'; \
  echo 'PermitRootLogin no'; \
  } > /etc/ssh/sshd_config.d/hof-probe.conf

# The host key and authorized_keys are bind-mounted read-only at
# /hof-keys by the test script (freshly generated per run, host-owned) -
# entrypoint.sh installs them with correct container-side ownership/
# permissions on every start rather than relaxing StrictModes to
# tolerate the host-owned mount directly.
COPY entrypoint.sh /usr/local/bin/hof-probe-entrypoint.sh
RUN chmod +x /usr/local/bin/hof-probe-entrypoint.sh

EXPOSE 22
CMD ["/usr/local/bin/hof-probe-entrypoint.sh"]
