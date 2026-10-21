#!/bin/sh
# Installs the Heimdall Sentinel service on a systemd system.
#
# It creates a dedicated account, the directories the daemon needs, the
# passphrase credential and the unit file, then enables the service. It does
# not start it: the operator should read the summary below before the first
# run, because the first run provisions an identity that Core has to pin.
#
# Run it as root:
#     sudo sh deploy/systemd/install.sh
#
# The passphrase is read from the terminal, or taken from HEIMDALL_PASSPHRASE
# if it is set. It is never passed on a command line, where every process on
# the box could read it.

set -eu

PREFIX="${PREFIX:-/usr/local/bin}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
STATE_DIR="${STATE_DIR:-/var/lib/heimdall}"
RUN_DIR="${RUN_DIR:-/run/heimdall}"
CREDENTIAL="${CREDENTIAL:-/etc/heimdall/passphrase}"
SERVICE_USER="${SERVICE_USER:-heimdall}"
SERVICE_GROUP="${SERVICE_GROUP:-heimdall}"
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { printf '%s\n' "$*"; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        say "this installer needs to run as root"
        exit 1
    fi
}

need_binary() {
    if ! command -v "$1" >/dev/null 2>&1; then
        say "missing: $1"
        exit 1
    fi
}

create_account() {
    if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        say "group $SERVICE_GROUP exists"
    else
        groupadd --system "$SERVICE_GROUP"
        say "created group $SERVICE_GROUP"
    fi
    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        say "user $SERVICE_USER exists"
    else
        useradd --system --gid "$SERVICE_GROUP" --home-dir "$STATE_DIR" \
            --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
        say "created user $SERVICE_USER"
    fi
}

install_binary() {
    if [ ! -f "$HERE/../../target/release/heimdall-sentinel" ]; then
        say "no release build found; run: cargo build --release -p heimdall-sentinel"
        exit 1
    fi
    install -m 0755 "$HERE/../../target/release/heimdall-sentinel" "$PREFIX/heimdall-sentinel"
    say "installed $PREFIX/heimdall-sentinel"
}

install_directories() {
    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR"
    install -d -m 0700 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$STATE_DIR/baselines"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$RUN_DIR"
    install -d -m 0750 -o root -g root "$(dirname "$CREDENTIAL")"
    say "prepared $STATE_DIR and $RUN_DIR"
}

write_credential() {
    if [ -f "$CREDENTIAL" ]; then
        say "credential $CREDENTIAL exists; leaving it alone"
        return
    fi
    passphrase="${HEIMDALL_PASSPHRASE:-}"
    if [ -z "$passphrase" ]; then
        if [ -t 0 ]; then
            printf 'passphrase for the heimdall keystore: ' >/dev/stderr
            stty -echo
            IFS= read -r passphrase
            stty echo
            printf '\n' >/dev/stderr
        else
            say "no passphrase given; set HEIMDALL_PASSPHRASE or run this from a terminal"
            exit 1
        fi
    fi
    printf '%s' "$passphrase" >"$CREDENTIAL"
    chown root:root "$CREDENTIAL"
    chmod 0400 "$CREDENTIAL"
    say "wrote $CREDENTIAL (0400, root only)"
}

install_unit() {
    install -m 0644 "$HERE/heimdall-sentinel.service" "$UNIT_DIR/heimdall-sentinel.service"
    systemctl daemon-reload
    systemctl enable heimdall-sentinel.service
    say "enabled heimdall-sentinel.service"
}

summary() {
    cat <<EOF

The service is installed and enabled but not started.

Before the first start:

  1. Start the service:      systemctl start heimdall-sentinel
  2. Read its identity:      journalctl -u heimdall-sentinel -n 20
     The identity is printed on the first run and is also written to
     $STATE_DIR/published/sentinel.identity
  3. Pin it in Core, by setting HEIMDALL_SENTINEL_ID to the hex identity
     before starting the shell.
  4. Point Core at the socket, and let it publish its identity where the
     daemon will look for it:
       export HEIMDALL_ENDPOINT=$RUN_DIR/heimdall-sentinel.sock
       export HEIMDALL_PUBLISH_DIR=$RUN_DIR/published
     and add the operator's account to the $SERVICE_GROUP group so the
     0660 socket and the runtime directory can be reached:
         sudo usermod -aG $SERVICE_GROUP <user>

Containment is advisory until the daemon is started with --allow-containment
and a containment policy that names what may be contained. The unit as
installed does not enable it.
EOF
}

need_root
need_binary install
need_binary systemctl
create_account
install_binary
install_directories
write_credential
install_unit
summary
