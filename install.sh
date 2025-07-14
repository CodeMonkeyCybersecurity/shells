#!/usr/bin/env bash
set -euo pipefail
trap 'echo " Installation failed on line $LINENO"; exit 1' ERR

log() { echo "[$1] $2"; }

# --- Platform Detection ---
PLATFORM=""
IS_LINUX=false
IS_MAC=false
IS_RHEL=false
IS_DEBIAN=false

detect_platform() {
  case "$(uname -s)" in
    Linux)  
      PLATFORM="linux"
      IS_LINUX=true
      # Detect Linux distribution
      if [ -f /etc/redhat-release ] || [ -f /etc/centos-release ] || [ -f /etc/fedora-release ]; then
        IS_RHEL=true
        log INFO " Detected RHEL-based system"
      elif [ -f /etc/debian_version ] || command -v apt-get >/dev/null 2>&1; then
        IS_DEBIAN=true
        log INFO " Detected Debian-based system"
      fi
      ;;
    Darwin) PLATFORM="mac"; IS_MAC=true ;;
    *) log ERR " Unsupported OS: $(uname -s)"; exit 1 ;;
  esac
  log INFO " Detected platform: $PLATFORM"
}

# --- Globals ---
Shells_USER="shells"
Shells_BINARY_NAME="shells"
Shells_SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
Shells_BUILD_PATH="$Shells_SRC_DIR/$Shells_BINARY_NAME"
INSTALL_PATH="/usr/local/bin/$Shells_BINARY_NAME"

# Go installation settings
GO_VERSION="1.23.4"
GO_INSTALL_DIR="/usr/local"

# --- Directories ---
# These are the *default* system-wide paths.
# If Shells CLI supports user-specific configs, the Go application
# should handle XDG Base Directory specification (e.g., ~/.config/shells)
# when run as a non-root user.
if $IS_MAC; then
  SECRETS_DIR="$HOME/Library/Application Support/shells/secrets"
  CONFIG_DIR="$HOME/Library/Application Support/shells/config"
  LOG_DIR="$HOME/Library/Logs/shells"
else
  SECRETS_DIR="/var/lib/shells/secrets"
  CONFIG_DIR="/etc/shells"
  LOG_DIR="/var/log/shells"
fi

update_system_packages() {
  if $IS_RHEL; then
    log INFO " Updating RHEL-based system packages..."
    if command -v dnf >/dev/null 2>&1; then
      dnf update -y
    elif command -v yum >/dev/null 2>&1; then
      yum update -y
    else
      log ERR " Neither dnf nor yum found on RHEL-based system"
      exit 1
    fi
  elif $IS_DEBIAN; then
    log INFO " Updating Debian-based system packages..."
    apt-get update -y
    apt-get upgrade -y
  elif $IS_MAC; then
    log INFO " Skipping system update on macOS (use brew upgrade manually if needed)"
  fi
}

install_go() {
  local need_go_install=false
  local current_version=""

  # Check if Go needs to be installed or updated
  if ! command -v go >/dev/null 2>&1; then
    log INFO " Go is not installed"
    need_go_install=true
  else
    current_version=$(go version | awk '{print $3}' | sed 's/go//')
    log INFO " Detected Go version: $current_version"
    
    # Simple version comparison - check if current version is at least the required version
    if printf '%s\n%s\n' "$GO_VERSION" "$current_version" | sort -V | head -n1 | grep -q "^$GO_VERSION$"; then
      log INFO " Go is already up-to-date (version $current_version >= $GO_VERSION)"
    else
      log INFO " Go version is older (wanted: $GO_VERSION, found: $current_version)"
      need_go_install=true
    fi
  fi

  if [ "$need_go_install" = true ]; then
    if $IS_MAC; then
      log INFO " Installing Go via Homebrew..."
      if ! command -v brew >/dev/null 2>&1; then
        log ERR " Homebrew not found. Please install it first: https://brew.sh/"
        exit 1
      fi
      brew install go
    else
      # Linux installation
      local arch="amd64"
      local os="linux"
      local go_tarball="go${GO_VERSION}.${os}-${arch}.tar.gz"
      local download_url="https://go.dev/dl/${go_tarball}"
      
      log INFO " Downloading Go ${GO_VERSION} from ${download_url}..."
      cd /tmp
      
      # Remove any existing tarball
      rm -f "$go_tarball"
      
      # Download with better error handling
      if ! curl -LO "$download_url"; then
        log ERR " Failed to download Go archive from ${download_url}"
        log ERR " Please check if the URL is correct and you have internet connection"
        exit 1
      fi
      
      if [ ! -f "$go_tarball" ]; then
        log ERR " Failed to download Go archive - file not found after download"
        exit 1
      fi
      
      # Verify download
      if ! file "$go_tarball" | grep -q "gzip compressed data"; then
        log ERR " Download failed or was not a valid tarball"
        exit 1
      fi
      
      log INFO " Extracting Go archive to ${GO_INSTALL_DIR}..."
      rm -rf "${GO_INSTALL_DIR}/go"
      tar -C "${GO_INSTALL_DIR}" -xzf "$go_tarball"
      
      # Set up environment variables system-wide
      local profile_file="/etc/profile.d/go.sh"
      log INFO " Setting up Go environment in ${profile_file}..."
      tee "${profile_file}" >/dev/null <<EOF
export PATH=\$PATH:/usr/local/go/bin
EOF
      
      # Symlink for global access
      if [ ! -f /usr/bin/go ]; then
        log INFO "🔗 Creating symlink for global Go access..."
        ln -sf /usr/local/go/bin/go /usr/bin/go
      fi
      
      # Clean up
      rm -f "$go_tarball"
      
      # Update PATH for current script execution
      export PATH="${GO_INSTALL_DIR}/go/bin:$PATH"
      
      log INFO " Go installed successfully"
    fi
  fi
  
  # Verify Go installation
  if command -v go >/dev/null 2>&1; then
    log INFO "Go version: $(go version)"
    
    # Test if we can actually use Go (not just find the binary)
    if ! go version >/dev/null 2>&1; then
      log ERR " Go binary found but not functional"
      exit 1
    fi
  else
    log ERR " Go installation verification failed"
    exit 1
  fi
}

install_github_cli() {
  if command -v gh >/dev/null 2>&1; then
    log INFO " GitHub CLI is already installed: $(gh --version | head -n1)"
    return
  fi
  
  log INFO " Installing GitHub CLI..."
  
  if $IS_MAC; then
    if ! command -v brew >/dev/null 2>&1; then
      log ERR " Homebrew not found. Please install it first: https://brew.sh/"
      exit 1
    fi
    brew install gh
  elif $IS_RHEL; then
    # Install dnf-plugins-core if not available
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y dnf-plugins-core
      
      # Remove any stale local repo
      if [ -f "/etc/yum.repos.d/opt_shells.repo" ]; then
        log INFO "Removing stale local repo: /etc/yum.repos.d/opt_shells.repo"
        rm -f /etc/yum.repos.d/opt_shells.repo
      fi
      
      # Add GitHub CLI repo if not already added
      if ! dnf repolist | grep -q "github-cli"; then
        dnf config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
      fi
      
      dnf install -y gh
    elif command -v yum >/dev/null 2>&1; then
      # Fallback to yum for older RHEL systems
      yum install -y yum-utils
      yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
      yum install -y gh
    fi
  elif $IS_DEBIAN; then
    # Install GitHub CLI on Debian-based systems
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
    chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null
    apt-get update
    apt-get install -y gh
  else
    log ERR " Unsupported Linux distribution for GitHub CLI installation"
    exit 1
  fi
  
  # Verify installation
  if command -v gh >/dev/null 2>&1; then
    log INFO " GitHub CLI installed: $(gh --version | head -n1)"
  else
    log ERR " GitHub CLI installation verification failed"
    exit 1
  fi
}

check_prerequisites() {
  local go_found=false

  # 1. Check if 'go' is in the current PATH
  if command -v go >/dev/null; then
    log INFO " Go found in current PATH: $(command -v go)"
    go_found=true
  # 2. Check the standard /usr/local/go/bin/go location directly
  elif [[ -x "/usr/local/go/bin/go" ]]; then
    export PATH="/usr/local/go/bin:$PATH" # Temporarily add to PATH for this script's execution
    log INFO " Go found at standard installation path: /usr/local/go/bin/go"
    go_found=true
  # 3. Check the user's HOME/go/bin/go location directly (as a fallback)
  elif [[ -x "$HOME/go/bin/go" ]]; then
    export PATH="$HOME/go/bin:$PATH" # Temporarily add to PATH for this script's execution
    log INFO " Go found at user home path: $HOME/go/bin/go"
    go_found=true
  fi

  if ! $go_found; then
    log INFO " Go executable not found. Will install Go automatically."
    install_go
  else
    # Check Go version and potentially upgrade
    install_go
  fi

  # Install GitHub CLI if not present
  install_github_cli

  # Verify Go is now available
  log INFO "Go detected and ready. Version details: $(go version)"

  if $IS_LINUX; then
    for cmd in useradd usermod visudo stat; do
      command -v "$cmd" >/dev/null || { log ERR "Missing required command: $cmd"; exit 1; }
    done
  fi
}

build_shells_binary() {
  log INFO " Building Shells..."
  cd "$Shells_SRC_DIR"
  rm -rf "$Shells_BINARY_NAME"
  
  # Set environment variables to help with toolchain issues
  export GOTOOLCHAIN=local
  export GOPROXY=direct
  
  # Use the 'go' command which should now be in PATH due to check_prerequisites
  if ! go build -o "$Shells_BINARY_NAME" .; then
    log ERR " Failed to build Shells binary"
    log ERR " This might be due to Go version mismatch or missing dependencies"
    log ERR " Current Go version: $(go version)"
    log ERR " Required Go version from go.mod: $(grep '^go ' go.mod | cut -d' ' -f2)"
    exit 1
  fi
}

show_existing_checksum() {
  if [ -f "$INSTALL_PATH" ]; then
    log INFO " Existing installed binary SHA256:"
    # Use command -v for robustness, or ensure shasum is on Mac
    command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
  else
    log INFO " No existing installed binary to replace"
  fi
}

install_binary() {
  log INFO " Installing to $INSTALL_PATH"
  if $IS_MAC; then
    # On macOS, sudo is typically implied for /usr/local/bin
    sudo rm -rf "$INSTALL_PATH" || log ERR "Failed to remove existing binary at $INSTALL_PATH. Permissions issue?"
    sudo cp "$Shells_BUILD_PATH" "$INSTALL_PATH" || log ERR "Failed to copy binary to $INSTALL_PATH. Permissions issue?"
    sudo chmod 755 "$INSTALL_PATH" || log ERR "Failed to set permissions on $INSTALL_PATH."
  else
    # Linux handling: re-run with sudo if not already root
    if [[ "$EUID" -ne 0 ]]; then
      log INFO " Re-running with sudo to ensure proper permissions..."
      # Use `bash -c` to ensure the environment is inherited correctly when `sudo` re-runs
      exec sudo bash -c "export PATH=\"$PATH\"; \"$0\" \"$@\""
    fi
    rm -rf "$INSTALL_PATH" || log ERR "Failed to remove existing binary at $INSTALL_PATH. Permissions issue?"
    cp "$Shells_BUILD_PATH" "$INSTALL_PATH" || log ERR "Failed to copy binary to $INSTALL_PATH. Permissions issue?"
    chown root:root "$INSTALL_PATH" || log ERR "Failed to change ownership of $INSTALL_PATH."
    chmod 755 "$INSTALL_PATH" || log ERR "Failed to set permissions on $INSTALL_PATH."
  fi
}

show_new_checksum() {
  log INFO " New installed binary SHA256:"
  command -v sha256sum >/dev/null && sha256sum "$INSTALL_PATH" || shasum -a 256 "$INSTALL_PATH"
}

create_directories() {
  log INFO " Creating system-wide secrets, config, and log directories: $SECRETS_DIR, $CONFIG_DIR, $LOG_DIR"
  # Ensure directories are created as root if running with sudo
  mkdir -p "$SECRETS_DIR" "$CONFIG_DIR" "$LOG_DIR" || log ERR "Failed to create directories."
  chmod 700 "$SECRETS_DIR" || log ERR "Failed to set permissions on $SECRETS_DIR."
  chmod 755 "$LOG_DIR" || log ERR "Failed to set permissions on $LOG_DIR."

  # This is where the core logic for user-runnable commands comes in.
  # If Shells can run certain commands as a regular user, it needs to access
  # config/log/secret files *owned by that user*.
  # The recommended approach is for the Go application itself to determine
  # paths based on the current user and XDG Base Directory spec.
  # For the shell script, we can at least ensure base permissions are not overly restrictive for other users
  # while maintaining security for the 'shells' system user.

  # Example: Make config directory readable by others (if configs aren't secrets)
  # You might want to copy example configs here and make them user-readable
  # chmod 755 "$CONFIG_DIR" # Only if config files themselves are not sensitive or are templates.

  # Note: The `setup_linux_user` function later changes ownership to `shells:shells`.
  # This part is installing for the system service user.
}

main() {
  detect_platform
  
  # Update system packages first (Linux only, requires root)
  if $IS_LINUX; then
    if [[ "$EUID" -eq 0 ]]; then
      update_system_packages
    else
      log INFO " Skipping system package update (not running as root)"
    fi
  fi
  
  check_prerequisites
  build_shells_binary
  show_existing_checksum
  install_binary "$@"
  show_new_checksum
  create_directories
  echo
  log INFO " Shells installation complete!"
  log INFO "The 'shells' binary has been installed to '$INSTALL_PATH'."
  log INFO "This path is typically included in your user's PATH."
  log INFO "You should now be able to run 'shells --help' directly."
  echo
  log INFO "NOTE: Commands requiring elevated privileges (e.g., system configuration, user management, service control)"
  log INFO "      will still require 'sudo shells [command]'. For example: 'sudo shells create user'."
  log INFO "      Log files are located in '$LOG_DIR' and configuration in '$CONFIG_DIR'."
}

main "$@"
