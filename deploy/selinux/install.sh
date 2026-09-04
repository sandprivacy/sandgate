#!/bin/sh
# Build and load the sandgate ssh-guard SELinux module. Run as root on the
# server, from this directory. Needs: policycoreutils, checkpolicy
#   dnf install -y policycoreutils checkpolicy policycoreutils-python-utils
set -eu

cd "$(dirname "$0")"
checkmodule -M -m -o sandgate-sshguard.mod sandgate-sshguard.te
semodule_package -o sandgate-sshguard.pp -m sandgate-sshguard.mod
semodule -i sandgate-sshguard.pp
echo "sandgate-sshguard policy loaded."
echo "Now test a login. If it is still refused, read the denials and send them our way:"
echo "  ausearch -m avc -ts recent | audit2allow"
