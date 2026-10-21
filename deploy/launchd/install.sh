#!/bin/sh
# Installs the Heimdall Sentinel daemon on macOS.
#
# It creates the account, the directories, the plist and the launchd job. It
# does not start the daemon: read the summary before the first run, because
# the first run provisions an identity that Core has to pin.
#
# Run it as root:
#     sudo sh deploy/launchd/install.sh
#
# The passphrase is read from the terminal, or taken from HEIMDALL_PASSPHRASE.
# It is never passed on a command line.

set -eu

PREFIX="${PREFIX:-/usr/local/bin}"
PLIST_DIR="${PLIST_DIR:-/Library/LaunchDaemons}"
STATE_DIR="${STATE_DIR:-/var/lib/heimdall}"
RUN_DIR="${RUN_DIR:-/var/run/heimdall}"
LOG_DIR="${LOG_DIR:-/var/log/heimdall}"
CREDENTIAL="${CREDENTIAL:-/etc/heimdall/passphrase}"
SERVICE_USER="${SERVICE_USER:-heimdall}"
SERVICE_GROUP="${SERVICE_GROUP:-heimdall}"
SERVICE_GID="${SERVICE_GID:-880}"
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { printf '%s\n' "$*"; }

need_root() {
    if [ "$(id -u)" -ne 0 ]; then
        say "this installer needs to run as root"
        exit 1
    fi
}

create_account() {
    if dscl . -read "/Users/$SERVICE_USER" RecordName >/dev/null 2>&1; then
        say "user $SERVICE_USER exists"
    else
        # The identifiers are fixed rather than chosen, so the account is the
        # same one on every machine that installs this. A host that already
        # uses 880 is a host where this should not be installed.
        if dscl . -read "/Groups/$SERVICE_GROUP" PrimaryGroupID >/dev/null 2>&1; then
            say "group $SERVICE_GROUP exists"
        else
            dscl . -create "/Groups/$SERVICE_GROUP" GroupName "$SERVICE_GROUP"
            dscl . -create "/Groups/$SERVICE_GROUP" PrimaryGroupID "$SERVICE_GID"
            say "created group $SERVICE_GROUP"
        fi
        dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
        dscl . -create "/Users/$SERVICE_USER" UniqueID "$SERVICE_GID"
        dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID "$SERVICE_GID"
        dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
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
    # The runtime directory is group-writable: the operator's console
    # publishes its identity there for the daemon to pin, and the socket in
    # it is reachable by the group.
    install -d -m 0770 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$RUN_DIR"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$LOG_DIR"
    install -d -m 0750 -o root -g wheel "$(dirname "$CREDENTIAL")"
    say "prepared $STATE_DIR, $RUN_DIR and $LOG_DIR"
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
    chown root:wheel "$CREDENTIAL"
    chmod 0400 "$CREDENTIAL"
    say "wrote $CREDENTIAL (0400, root only)"
}

install_plist() {
    install -m 0644 "$HERE/com.heimdall.sentinel.plist" \
        "$PLIST_DIR/com.heimdall.sentinel.plist"
    chown root:wheel "$PLIST_DIR/com.heimdall.sentinel.plist"
    say "installed $PLIST_DIR/com.heimdall.sentinel.plist"
}

summary() {
    cat <<EOF

The daemon is installed but not started.

Before the first start:

  1. Start it:              sudo launchctl bootstrap system \\
                               $PLIST_DIR/com.heimdall.sentinel.plist
  2. Read its identity:     sudo tail -n 20 $LOG_DIR/sentinel.log
     The identity is also written to $STATE_DIR/published/sentinel.identity
  3. Pin it in Core, by setting HEIMDALL_SENTINEL_ID to the hex identity
     before starting the shell.
  4. Point Core at the socket:
       export HEIMDALL_ENDPOINT=$RUN_DIR/heimdall-sentinel.sock
     and let it publish its identity where the daemon will look for it:
       export HEIMDALL_PUBLISH_DIR=$RUN_DIR/published
     and add the operator's account to the $SERVICE_GROUP group so the
     0660 socket and the runtime directory can be reached:
       sudo dseditgroup -o edit -a <user> -t user $SERVICE_GROUP

Containment is advisory until the daemon is started with --allow-containment
and a containment policy that names what may be contained.
EOF
}

need_root
create_account
install_binary
install_directories
write_credential
install_plist
summary
