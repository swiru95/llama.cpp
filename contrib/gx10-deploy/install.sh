#!/usr/bin/env bash
# Install this fork's build of llama-server as a systemd service.
#
# Usage (run from anywhere, after building):
#   cmake --build build --target llama-server -j$(nproc)
#   sudo contrib/gx10-deploy/install.sh
#
# Safe to re-run: it will not overwrite an existing /etc/llama-server/*
# config, and re-copies the binaries each time so `install.sh` after a
# rebuild is the normal upgrade path.
#
# Override the install location with INSTALL_PREFIX=/some/path sudo -E ...

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: run as root (sudo $0)" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_BIN="$REPO_ROOT/build/bin"
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/llama-server}"
CONFIG_DIR="/etc/llama-server"
DATA_DIR="/var/lib/llama-server"
LOG_DIR="/var/log/llama-server"
SERVICE_USER="llama-server"

if [ ! -x "$BUILD_BIN/llama-server" ]; then
    echo "error: $BUILD_BIN/llama-server not found - build first:" >&2
    echo "  cmake --build build --target llama-server -j\$(nproc)" >&2
    exit 1
fi

echo "==> system user '$SERVICE_USER'"
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "    created"
else
    echo "    already exists"
fi

echo "==> GPU device group membership"
for grp in video render; do
    if getent group "$grp" >/dev/null 2>&1; then
        usermod -aG "$grp" "$SERVICE_USER"
        echo "    added $SERVICE_USER to '$grp'"
    fi
done

echo "==> binaries -> $INSTALL_PREFIX/bin"
# Copying build/bin/ wholesale (the binary plus every .so it already links
# against, in the exact layout that has been running successfully from the
# build tree) rather than `cmake --install`: not every internal target in
# this tree has a matching install() rule, and a partial install can
# silently drop a runtime dependency that only surfaces as a linker error
# at service start. The unit's LD_LIBRARY_PATH covers this regardless of
# how each .so's RPATH was set at link time.
mkdir -p "$INSTALL_PREFIX/bin"
cp -a "$BUILD_BIN/." "$INSTALL_PREFIX/bin/"

echo "==> $CONFIG_DIR, $DATA_DIR, $LOG_DIR"
mkdir -p "$CONFIG_DIR" "$DATA_DIR/cache" "$LOG_DIR"

if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp "$REPO_ROOT/contrib/gx10-deploy/config.yaml.example" "$CONFIG_DIR/config.yaml"
    echo "    wrote $CONFIG_DIR/config.yaml - EDIT THE PLACEHOLDER API KEY BEFORE STARTING"
else
    echo "    $CONFIG_DIR/config.yaml already exists, leaving it as-is"
fi
if [ ! -f "$CONFIG_DIR/models.ini" ]; then
    cp "$REPO_ROOT/contrib/gx10-deploy/models.ini.example" "$CONFIG_DIR/models.ini"
    echo "    wrote $CONFIG_DIR/models.ini"
else
    echo "    $CONFIG_DIR/models.ini already exists, leaving it as-is"
fi

chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR" "$LOG_DIR"
chown -R "root:$SERVICE_USER" "$CONFIG_DIR"
chmod 750 "$CONFIG_DIR"
chmod 640 "$CONFIG_DIR"/*.yaml "$CONFIG_DIR"/*.ini 2>/dev/null || true

# Offer to migrate the invoking (non-root) user's existing HF model cache,
# since ProtectHome=true in the unit means the service cannot read it later.
ORIG_USER="${SUDO_USER:-}"
if [ -n "$ORIG_USER" ]; then
    ORIG_HOME="$(getent passwd "$ORIG_USER" | cut -d: -f6)"
    ORIG_HF_HUB="$ORIG_HOME/.cache/huggingface/hub"
    if [ -d "$ORIG_HF_HUB" ] && [ -z "$(ls -A "$DATA_DIR/cache" 2>/dev/null)" ]; then
        read -r -p "==> copy $ORIG_USER's existing HF model cache into $DATA_DIR/cache? [y/N] " ans
        if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
            cp -a "$ORIG_HF_HUB/." "$DATA_DIR/cache/"
            chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR/cache"
            echo "    copied"
        fi
    fi
fi

echo "==> systemd unit"
sed "s#@INSTALL_PREFIX@#$INSTALL_PREFIX#g" \
    "$REPO_ROOT/contrib/gx10-deploy/llama-server.service" \
    > /etc/systemd/system/llama-server.service
systemctl daemon-reload
echo "    installed /etc/systemd/system/llama-server.service"

cat <<EOF

Install complete. Before starting:
  1. Edit $CONFIG_DIR/config.yaml - replace the placeholder API key
     (openssl rand -hex 32 makes a good one)
  2. Edit $CONFIG_DIR/models.ini if you want different models than the
     Qwen3-Coder / Qwen3-32B example
  3. If no cache was copied above, pre-pull each model as the service user
     (llama-server has no download-only mode - run it for real once, on a
     scratch port, and Ctrl+C after "model loaded" / "listening on" appears;
     this also confirms the service account can load the model, not just
     download it):
       sudo -u $SERVICE_USER env LLAMA_CACHE=$DATA_DIR/cache \\
         $INSTALL_PREFIX/bin/llama-server -hf <repo>:<quant> --port 18080

Then:
  sudo systemctl enable --now llama-server
  sudo journalctl -u llama-server -f
EOF
