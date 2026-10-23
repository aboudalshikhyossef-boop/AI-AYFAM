#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT="${1:-$ROOT_DIR/dist/ai-ayfam.deb}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to build the package" >&2
    exit 1
}

mkdir -p "$(dirname "$OUTPUT")"
install -Dm644 "$ROOT_DIR/packaging/deb/DEBIAN/control" "$STAGE/DEBIAN/control"
install -Dm644 "$ROOT_DIR/packaging/deb/usr/share/applications/ayfam.desktop" \
    "$STAGE/usr/share/applications/ayfam.desktop"

APP_DIR="$STAGE/usr/lib/ai-ayfam"
mkdir -p "$APP_DIR"
for path in main.py brain config core engine reports tools ui utils resources metadata.json requirements.txt; do
    cp -a "$ROOT_DIR/$path" "$APP_DIR/"
done

mkdir -p "$STAGE/usr/bin"
cat > "$STAGE/usr/bin/ayfam" <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/lib/ai-ayfam/main.py "$@"
EOF
cat > "$STAGE/usr/bin/ayfam-gui" <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/lib/ai-ayfam/main.py --gui "$@"
EOF
chmod 0755 "$STAGE/usr/bin/ayfam" "$STAGE/usr/bin/ayfam-gui"

dpkg-deb --build --root-owner-group "$STAGE" "$OUTPUT" >/dev/null
echo "Built $OUTPUT"
