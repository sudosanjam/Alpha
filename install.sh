#!/usr/bin/env bash
# ==============================================================================
# ALPHA: Rootless Termux Wireless Observation Platform Installer
# ==============================================================================
set -e

echo "============================================================"
echo "          ALPHA WIRELESS OBSERVATION PLATFORM               "
echo "                 Rootless Termux Installer                  "
echo "============================================================"

# 1. Detect Environment
IS_TERMUX=0
if [ -n "$TERMUX_VERSION" ] || [[ "$PREFIX" == *"com.termux"* ]]; then
    IS_TERMUX=1
    echo "[+] Detected Termux environment (v${TERMUX_VERSION:-unknown})"
else
    echo "[*] Standard Linux / POSIX environment detected."
fi

# 2. Check Python Version
if ! command -v python &> /dev/null && ! command -v python3 &> /dev/null; then
    echo "[!] Python is not installed."
    if [ $IS_TERMUX -eq 1 ]; then
        echo "[*] Installing Python via pkg..."
        pkg update -y && pkg install -y python
    else
        echo "[!] Please install Python 3.10+ and re-run this script."
        exit 1
    fi
fi

PYTHON_BIN=$(command -v python3 || command -v python)
PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Using Python $PY_VER ($PYTHON_BIN)"

# Verify Python >= 3.10
$PYTHON_BIN -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"

# 3. Check Termux:API package
if [ $IS_TERMUX -eq 1 ]; then
    if ! command -v termux-wifi-scaninfo &> /dev/null; then
        echo "[*] Notice: 'termux-wifi-scaninfo' not found in PATH."
        echo "    To enable live Wi-Fi observation, run:"
        echo "      pkg install termux-api"
        echo "    and ensure the Termux:API APK is installed from F-Droid with Location permission granted."
    else
        echo "[+] Termux:API wireless scanning utility found: $(command -v termux-wifi-scaninfo)"
    fi
fi

# 4. Install Python Dependencies & Package
echo "[*] Installing Alpha package..."
# Do not upgrade pip (Termux forbids self-upgrading pip as it is managed by pkg)
if $PYTHON_BIN -m pip --version &> /dev/null; then
    if $PYTHON_BIN -m pip install --help 2>&1 | grep -q "break-system-packages"; then
        $PYTHON_BIN -m pip install --break-system-packages -e . 2>/dev/null || true
    else
        $PYTHON_BIN -m pip install -e . 2>/dev/null || true
    fi
fi

# 5. Create Configuration & Data Directories
CONFIG_DIR="${ALPHA_CONFIG_DIR:-$HOME/.config/alpha}"
DATA_DIR="${ALPHA_DATA_DIR:-$HOME/.local/share/alpha}"

mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR/logs"

echo "[+] Initialized storage directories:"
echo "    Config: $CONFIG_DIR"
echo "    Data:   $DATA_DIR"

# 6. Ensure Standalone 'alpha' Command in PATH
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR=""

if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ] && [ -w "$PREFIX/bin" ]; then
    BIN_DIR="$PREFIX/bin"
elif [ -d "$HOME/.local/bin" ]; then
    BIN_DIR="$HOME/.local/bin"
elif [ -d "$HOME/bin" ]; then
    BIN_DIR="$HOME/bin"
else
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
fi

cat <<EOF > "$BIN_DIR/alpha"
#!/usr/bin/env bash
export PYTHONPATH="$REPO_DIR:\$PYTHONPATH"
exec "$PYTHON_BIN" -m alpha.cli "\$@"
EOF
chmod +x "$BIN_DIR/alpha"
echo "[+] Created Alpha launcher: $BIN_DIR/alpha"

# 7. Run Automated Self-Test Verification
echo ""
echo "[*] Running Alpha automated self-test verification..."
$PYTHON_BIN -m alpha.cli --self-test

echo ""
echo "============================================================"
echo "               ALPHA INSTALLATION COMPLETE                  "
echo "============================================================"
echo "Usage:"
echo "  alpha                 # Start interactive monitor"
echo "  alpha scan            # Run one-shot scan"
echo "  alpha --mock          # Run in mock/simulation mode"
echo "  alpha diagnostics     # Check hardware capabilities"
echo "  alpha --help          # Show all available commands"
echo "============================================================"
