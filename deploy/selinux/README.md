# ssh-guard on SELinux systems (RHEL, Rocky, Alma, Fedora)

`sandgate ssh-guard setup` validates the sshd configuration, self-tests
the hook and reloads sshd — and on an enforcing SELinux system every
login can still fail afterwards, with nothing on screen. The reason is
in `/var/log/audit/audit.log`: `sshd_t` is not allowed to execute an
interpreter, open a network connection, or write under `/tmp` while
authenticating someone.

The installer says so when it detects `getenforce` = `Enforcing`.

## Install the policy

```bash
dnf install -y policycoreutils checkpolicy policycoreutils-python-utils
curl -fsSL https://raw.githubusercontent.com/sandprivacy/sandgate/main/deploy/selinux/sandgate-sshguard.te -o sandgate-sshguard.te
curl -fsSL https://raw.githubusercontent.com/sandprivacy/sandgate/main/deploy/selinux/install.sh -o install.sh
sh install.sh
```

Then test a login **from another terminal** while your session stays
open, as always.

## If logins are still refused

```bash
ausearch -m avc -ts recent          # what was denied
ausearch -m avc -ts recent | audit2allow -M sandgate-local && semodule -i sandgate-local.pp
```

`audit2allow` writes a module that allows exactly what was denied. Read
it before loading it, and please open an issue with the denials so the
shipped policy can cover them.

## Status

This policy was written from the documented sshd_t rules and the hook's
real behaviour, **not** validated on an enforcing machine yet. Treat it
as a starting point that removes the known denials, and expect to add a
line or two on your distribution. The standalone binary (see releases)
reduces the surface: one file under `/usr/local/bin`, `bin_t`, no
`node_modules` to label.
