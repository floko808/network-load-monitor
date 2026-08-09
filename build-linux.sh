#!/bin/bash
#
# Build the Linux binaries (CLI + GUI) for the IEC 61850 Network Load Monitor.
#
# The build runs inside a Debian 12 (bookworm) container rather than on the
# host on purpose. PyInstaller does not bundle glibc — the frozen binary links
# against whatever glibc the build machine has, and glibc is only backwards
# compatible. Building on a newer distro therefore produces binaries that
# refuse to start on older ones. Debian 12 (glibc 2.36) is the oldest target
# we support, so building there covers Debian 12, Ubuntu 24.04 (glibc 2.39),
# and anything newer.
#
# Usage:  ./build-linux.sh          # from the repo root; needs docker
# Output: dist/network-monitor-linux-x86_64
#         dist/network-monitor-gui-linux-x86_64
#
# The Windows .exe builds are made separately, by running PyInstaller against
# the same two .spec files on a Windows host.

set -euo pipefail

IMAGE="debian:12"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Stage 2: inside the container. Re-entered via the docker run below.
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--in-container" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # python3-tk is needed at build time so PyInstaller can find and bundle
    # tkinter for the GUI; binutils provides the objdump/strip PyInstaller
    # uses when scanning for shared-library dependencies.
    apt-get install -y -qq --no-install-recommends \
        python3 python3-venv python3-dev python3-tk \
        binutils zlib1g-dev libffi-dev ca-certificates

    # Debian's system Python is externally managed, so pip needs a venv.
    python3 -m venv /venv
    /venv/bin/pip install --quiet --upgrade pip wheel
    /venv/bin/pip install --quiet -r /src/requirements.txt pyinstaller

    # /src is mounted read-only, so build in a scratch directory.
    mkdir -p /work && cd /work
    cp /src/monitor.py /src/monitor_gui.py \
       /src/network-monitor.spec /src/network-monitor-gui.spec .

    /venv/bin/pyinstaller --clean --noconfirm \
        --distpath /work/dist --workpath /work/build network-monitor.spec
    /venv/bin/pyinstaller --clean --noconfirm \
        --distpath /work/dist --workpath /work/build network-monitor-gui.spec

    # Platform-tagged names, so the Linux and Windows assets on a GitHub
    # release never collide.
    cp /work/dist/network-monitor     /out/network-monitor-linux-x86_64
    cp /work/dist/network-monitor-gui /out/network-monitor-gui-linux-x86_64
    chmod +x /out/network-monitor-linux-x86_64 /out/network-monitor-gui-linux-x86_64

    # The container runs as root, so hand the artifacts back to the invoking
    # user rather than leaving root-owned files in the host's dist/.
    chown "${HOST_UID:-0}:${HOST_GID:-0}" \
        /out/network-monitor-linux-x86_64 /out/network-monitor-gui-linux-x86_64

    exit 0
fi

# ---------------------------------------------------------------------------
# Stage 1: on the host. Set up the container and hand off to stage 2.
# ---------------------------------------------------------------------------
command -v docker >/dev/null || {
    echo "docker not found — it is required to build against Debian 12's glibc." >&2
    exit 1
}

mkdir -p "$REPO_DIR/dist"

docker run --rm \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$REPO_DIR:/src:ro" \
    -v "$REPO_DIR/dist:/out" \
    -v "$REPO_DIR/build-linux.sh:/build-linux.sh:ro" \
    "$IMAGE" bash /build-linux.sh --in-container

echo
echo "Built:"
ls -l "$REPO_DIR/dist/network-monitor-linux-x86_64" \
      "$REPO_DIR/dist/network-monitor-gui-linux-x86_64"
echo
echo "SHA256:"
sha256sum "$REPO_DIR/dist/network-monitor-linux-x86_64" \
          "$REPO_DIR/dist/network-monitor-gui-linux-x86_64"
