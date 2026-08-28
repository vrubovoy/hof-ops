#!/bin/sh
# Installs the bind-mounted, freshly-generated (per test run) host key
# and authorized_keys with correct container-side ownership/permissions,
# then hands off to real systemd as PID 1 (ssh.service is already
# enabled - see the Dockerfile - so systemd starts sshd itself once it
# comes up, exactly like it would on a real target). Nothing here is
# baked into the image - the actual key material always comes from
# /hof-keys, mounted read-only by test/apply-acceptance.mjs.
set -eu

cp /hof-keys/host_key /etc/ssh/ssh_host_ed25519_key
chmod 600 /etc/ssh/ssh_host_ed25519_key
# Debian's openssh-server package pre-generates its own host keypair at
# install time - the .pub half left over from that doesn't match the
# private key we just installed, and sshd warns loudly about it.
# Regenerating the public half from the actual private key we're using
# clears that up instead of leaving a stale, mismatched file in place.
ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key > /etc/ssh/ssh_host_ed25519_key.pub

mkdir -p /home/hofprobe/.ssh
cp /hof-keys/authorized_keys /home/hofprobe/.ssh/authorized_keys
chown -R hofprobe:hofprobe /home/hofprobe/.ssh
chmod 700 /home/hofprobe/.ssh
chmod 600 /home/hofprobe/.ssh/authorized_keys

exec /lib/systemd/systemd
