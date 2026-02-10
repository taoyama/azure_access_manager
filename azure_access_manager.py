#!/usr/bin/env python3
"""
Azure NSG SSH/RDP Access Manager
=================================
A tool that detects the user's public IP address and configures Azure Network
Security Group (NSG) rules to allow SSH (Linux) or RDP (Windows) access to VMs.

Key features:
  - Auto-detects public IP via external services
  - Supports both Windows and WSL environments (auto-detected)
  - Auto-creates NSGs if none are associated with a VM's NIC or subnet
  - Removes duplicate NSG rules
  - Skips adding rules if an existing rule already allows the required access
  - Supports custom port overrides for SSH and RDP independently
  - Connectivity testing (TCP handshake) with VM power state detection
  - Interactive and CLI modes
  - Bulk operations across all VMs in a subscription
  - Remove all custom security rules from NSGs (cleanup)

Usage:
  python azure_access_manager.py                   # Interactive mode
  python azure_access_manager.py --all              # All VMs
  python azure_access_manager.py --test-only        # Test connectivity only
  python azure_access_manager.py --remove-rules     # Remove all custom rules
  python azure_access_manager.py --help             # Full help
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import urllib.request
import urllib.error
import socket
from typing import Optional


# ══════════════════════════════════════════════════════════════
# Default port numbers for SSH and RDP services.
# These can be overridden via --ssh-port and --rdp-port CLI flags.
# ══════════════════════════════════════════════════════════════
DEFAULT_SSH_PORT = "22"
DEFAULT_RDP_PORT = "3389"


# ══════════════════════════════════════════════════════════════
# ANSI Color Codes
# Provides colored terminal output for better readability.
# Colors are automatically disabled when stdout is not a TTY
# (e.g., when output is piped) or on Windows cmd.exe without
# virtual terminal processing support.
# ══════════════════════════════════════════════════════════════
class Colors:
    """ANSI escape codes for terminal colors and text formatting."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    ITALIC  = "\033[3m"
    UNDERLINE = "\033[4m"

    # Foreground colors
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    # Background colors
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"

    @classmethod
    def disable(cls):
        """
        Disable all color output by setting every color constant to an empty string.
        Called automatically when running in a non-TTY environment or when
        the --no-color flag is used.
        """
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


# Disable colors if stdout is not a TTY (e.g., piped to a file or another command)
if not sys.stdout.isatty():
    Colors.disable()

# On Windows, enable virtual terminal processing for ANSI escape codes.
# This is required for Windows 10+ to properly display colors in cmd.exe.
# If enabling fails (older Windows versions), colors are disabled entirely.
if platform.system() == "Windows":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        Colors.disable()


# ══════════════════════════════════════════════════════════════
# Unicode Box-Drawing Characters and Icons
# Used throughout the application for formatted terminal output
# including tables, section headers, status messages, and banners.
# ══════════════════════════════════════════════════════════════

# Double-line box-drawing (used for banners and major sections)
BOX_TL = "╔"   # Top-left corner
BOX_TR = "╗"   # Top-right corner
BOX_BL = "╚"   # Bottom-left corner
BOX_BR = "╝"   # Bottom-right corner
BOX_H  = "═"   # Horizontal line
BOX_V  = "║"   # Vertical line
BOX_ML = "╠"   # Middle-left tee
BOX_MR = "╣"   # Middle-right tee

# Single-line box-drawing (used for tables and info boxes)
LINE_H = "─"       # Horizontal line
LINE_V = "│"       # Vertical line
CORNER_TL = "┌"    # Top-left corner
CORNER_TR = "┐"    # Top-right corner
CORNER_BL = "└"    # Bottom-left corner
CORNER_BR = "┘"    # Bottom-right corner
TEE_L = "├"        # Left tee
TEE_R = "┤"        # Right tee

# Status and decoration icons
BULLET = "•"
ARROW  = "→"
CHECK  = "✓"
CROSS  = "✗"
WARN_ICON = "⚠"
INFO_ICON = "ℹ"
GEAR_ICON = "⚙"
LOCK_ICON = "🔒"
KEY_ICON  = "🔑"
GLOBE_ICON = "🌐"
SERVER_ICON = "🖥"
SHIELD_ICON = "🛡"
TRASH_ICON = "🗑"


# ══════════════════════════════════════════════════════════════
# Pretty Print Helper Functions
# These functions provide consistent, styled terminal output
# for various message types (info, success, warning, error)
# and formatting elements (tables, boxes, banners, dividers).
# ══════════════════════════════════════════════════════════════

def _width() -> int:
    """
    Get the current terminal width, capped at 80 columns.
    Falls back to 70 columns if the terminal size cannot be determined
    (e.g., when running in a non-interactive environment).
    """
    try:
        return min(os.get_terminal_size().columns, 80)
    except OSError:
        return 70


def print_banner():
    """
    Print the application title banner at startup.
    Displays the tool name and description inside a double-line box.
    """
    w = _width()
    title = "Azure NSG SSH/RDP Access Manager"
    subtitle = "Secure remote access configuration tool"

    print()
    print(f"  {Colors.CYAN}{BOX_TL}{BOX_H * (w - 4)}{BOX_TR}{Colors.RESET}")
    print(f"  {Colors.CYAN}{BOX_V}{Colors.RESET}  {Colors.BOLD}{Colors.WHITE}{SHIELD_ICON} {title}{Colors.RESET}{' ' * (w - len(title) - 8)}{Colors.CYAN}{BOX_V}{Colors.RESET}")
    print(f"  {Colors.CYAN}{BOX_V}{Colors.RESET}  {Colors.DIM}{subtitle}{Colors.RESET}{' ' * (w - len(subtitle) - 6)}{Colors.CYAN}{BOX_V}{Colors.RESET}")
    print(f"  {Colors.CYAN}{BOX_BL}{BOX_H * (w - 4)}{BOX_BR}{Colors.RESET}")
    print()


def print_section(title: str, icon: str = ""):
    """
    Print a major section header with horizontal rule lines.
    Used to visually separate different phases of the tool's execution
    (e.g., "Authentication", "Configuring NSG Rules", "Connectivity Tests").

    Args:
        title: The section title text.
        icon:  Optional emoji/icon to display before the title.
    """
    w = _width()
    prefix = f"{icon} " if icon else ""
    label = f" {prefix}{title} "
    line_len = w - len(label) - 2
    left = line_len // 2
    right = line_len - left
    print()
    print(f"  {Colors.BLUE}{LINE_H * left}{Colors.BOLD}{Colors.WHITE}{label}{Colors.RESET}{Colors.BLUE}{LINE_H * right}{Colors.RESET}")
    print()


def print_subsection(title: str):
    """
    Print a minor subsection header.
    Used for grouping related items within a section (e.g., per-NSG operations).

    Args:
        title: The subsection title text.
    """
    print(f"  {Colors.DIM}{LINE_H * 3}{Colors.RESET} {Colors.BOLD}{title}{Colors.RESET}")


def print_info(msg: str):
    """Print an informational message with a blue info icon."""
    print(f"  {Colors.BLUE}{INFO_ICON}{Colors.RESET}  {msg}")


def print_success(msg: str):
    """Print a success message with a green checkmark icon."""
    print(f"  {Colors.GREEN}{CHECK}{Colors.RESET}  {Colors.GREEN}{msg}{Colors.RESET}")


def print_warn(msg: str):
    """Print a warning message with a yellow warning icon."""
    print(f"  {Colors.YELLOW}{WARN_ICON}{Colors.RESET}  {Colors.YELLOW}{msg}{Colors.RESET}")


def print_error(msg: str):
    """Print an error message with a red cross icon."""
    print(f"  {Colors.RED}{CROSS}{Colors.RESET}  {Colors.RED}{msg}{Colors.RESET}")


def print_skip(msg: str):
    """Print a skip/bypass message with a magenta arrow icon."""
    print(f"  {Colors.MAGENTA}{ARROW}{Colors.RESET}  {Colors.MAGENTA}{msg}{Colors.RESET}")


def print_detail(msg: str):
    """
    Print a detail/sub-item message with indentation.
    Used for additional context or explanations under a primary message.
    """
    print(f"       {Colors.DIM}{msg}{Colors.RESET}")


def print_bullet(msg: str, indent: int = 2):
    """
    Print a bulleted list item with a cyan bullet character.

    Args:
        msg:    The text to display.
        indent: Number of leading spaces (default: 2).
    """
    spaces = " " * indent
    print(f"{spaces}  {Colors.CYAN}{BULLET}{Colors.RESET} {msg}")


def print_key_value(key: str, value: str, indent: int = 2):
    """
    Print a key-value pair in a consistent format.
    The key is displayed in dim text, the value in white.

    Args:
        key:    The label/key text.
        value:  The value text.
        indent: Number of leading spaces (default: 2).
    """
    spaces = " " * indent
    print(f"{spaces}  {Colors.DIM}{key}:{Colors.RESET} {Colors.WHITE}{value}{Colors.RESET}")


def print_table_row(cols: list, widths: list, color: str = ""):
    """
    Print a formatted table row with column alignment.

    Args:
        cols:   List of column values.
        widths: List of column widths (must match cols length).
        color:  Optional ANSI color code for the entire row.
    """
    row = ""
    for i, (col, width) in enumerate(zip(cols, widths)):
        col_str = str(col)
        if len(col_str) > width:
            col_str = col_str[:width - 1] + "…"
        if i == 0:
            row += f" {col_str:<{width}} "
        else:
            row += f" {col_str:<{width}} "
    if color:
        print(f"  {Colors.GRAY}{LINE_V}{Colors.RESET}{color}{row}{Colors.RESET}{Colors.GRAY}{LINE_V}{Colors.RESET}")
    else:
        print(f"  {Colors.GRAY}{LINE_V}{Colors.RESET}{row}{Colors.GRAY}{LINE_V}{Colors.RESET}")


def print_divider(style: str = "light"):
    """
    Print a horizontal divider line across the terminal width.

    Args:
        style: One of "light" (thin gray), "heavy" (blue double), or "double" (cyan double).
    """
    w = _width()
    if style == "heavy":
        print(f"  {Colors.BLUE}{BOX_H * (w - 4)}{Colors.RESET}")
    elif style == "double":
        print(f"  {Colors.CYAN}{BOX_H * (w - 4)}{Colors.RESET}")
    else:
        print(f"  {Colors.DIM}{LINE_H * (w - 4)}{Colors.RESET}")


def print_box(lines: list, color: str = Colors.CYAN):
    """
    Print multiple lines of text inside a single-line bordered box.
    Useful for displaying multi-line notes, tips, or troubleshooting hints.
    Long lines are wrapped to fit within the box width.

    Args:
        lines: List of text lines to display inside the box.
        color: ANSI color code for the box border (default: cyan).
    """
    w = _width()
    inner_w = w - 6

    # Pre-process lines: wrap long lines to fit within the box
    wrapped_lines = []
    for line in lines:
        if len(line) <= inner_w:
            wrapped_lines.append(line)
        else:
            # Wrap long lines, preserving leading whitespace for continuation
            remaining = line
            # Detect leading whitespace for indent on continuation lines
            stripped = remaining.lstrip()
            leading_spaces = len(remaining) - len(stripped)
            indent = " " * min(leading_spaces + 2, inner_w // 2)
            first = True
            while len(remaining) > inner_w:
                # Find a good break point (space) near the width limit
                break_at = remaining.rfind(" ", 0, inner_w)
                if break_at <= 0 or break_at < inner_w // 2:
                    # No good break point; hard break
                    break_at = inner_w
                wrapped_lines.append(remaining[:break_at])
                remaining = remaining[break_at:].lstrip()
                if first:
                    first = False
                if remaining:
                    remaining = indent + remaining
            if remaining:
                wrapped_lines.append(remaining)

    print(f"  {color}{CORNER_TL}{LINE_H * (inner_w + 2)}{CORNER_TR}{Colors.RESET}")
    for line in wrapped_lines:
        padding = inner_w - len(line)
        if padding < 0:
            line = line[:inner_w]
            padding = 0
        print(f"  {color}{LINE_V}{Colors.RESET} {line}{' ' * padding} {color}{LINE_V}{Colors.RESET}")
    print(f"  {color}{CORNER_BL}{LINE_H * (inner_w + 2)}{CORNER_BR}{Colors.RESET}")


def print_completion_banner(message: str = "All tasks completed successfully"):
    """
    Print a green bordered banner indicating successful completion.
    Displayed at the end of the tool's execution.

    Args:
        message: The completion message to display (default: generic success).
    """
    w = _width()
    print()
    print(f"  {Colors.GREEN}{BOX_TL}{BOX_H * (w - 4)}{BOX_TR}{Colors.RESET}")
    label = f" {CHECK} {message} "
    padding = w - len(label) - 4
    left_pad = padding // 2
    right_pad = padding - left_pad
    print(f"  {Colors.GREEN}{BOX_V}{Colors.RESET}{' ' * left_pad}{Colors.BOLD}{Colors.GREEN}{label}{Colors.RESET}{' ' * right_pad}{Colors.GREEN}{BOX_V}{Colors.RESET}")
    print(f"  {Colors.GREEN}{BOX_BL}{BOX_H * (w - 4)}{BOX_BR}{Colors.RESET}")
    print()


def print_vm_processing_header(vm_name: str, index: int = 0, total: int = 0):
    """
    Print a highlighted header when starting to process a specific VM.
    Shows the VM name and optional progress counter (e.g., [2/5]).

    Args:
        vm_name: Name of the VM being processed.
        index:   Current VM index (1-based). 0 to hide counter.
        total:   Total number of VMs. 0 to hide counter.
    """
    w = _width()
    counter = f" [{index}/{total}]" if total > 0 else ""
    label = f" {SERVER_ICON} Processing: {vm_name}{counter} "
    line_len = w - len(label)
    left = line_len // 2
    right = line_len - left
    print()
    print(f"  {Colors.YELLOW}{BOX_H * left}{Colors.BOLD}{Colors.WHITE}{label}{Colors.RESET}{Colors.YELLOW}{BOX_H * right}{Colors.RESET}")


def styled_input(prompt: str) -> str:
    """
    Display a styled input prompt and return the user's input.
    Uses a green arrow prefix for visual consistency.

    Args:
        prompt: The prompt text to display.

    Returns:
        The user's input string.
    """
    return input(f"  {Colors.GREEN}{ARROW}{Colors.RESET} {Colors.BOLD}{prompt}{Colors.RESET}")


# ══════════════════════════════════════════════════════════════
# Platform Detection
# Determines the runtime environment (Windows, WSL, Linux/macOS)
# and configures the Azure CLI command accordingly.
# WSL can use either native Linux az CLI or Windows az.cmd.
# ══════════════════════════════════════════════════════════════

def is_wsl() -> bool:
    """
    Detect if the script is running inside Windows Subsystem for Linux (WSL).
    Checks /proc/version for "microsoft" which is present in WSL kernels.

    Returns:
        True if running in WSL, False otherwise.
    """
    if platform.system() != "Linux":
        return False
    try:
        with open("/proc/version", "r") as f:
            return "microsoft" in f.read().lower()
    except FileNotFoundError:
        return False


def get_platform_info() -> dict:
    """
    Detect the current platform and return execution settings.
    Determines:
      - Which shell mode to use for subprocess calls
      - Which Azure CLI binary to invoke (az vs az.cmd)

    Returns:
        Dict with keys: 'platform' (str), 'shell' (bool), 'az_cmd' (str).
    """
    system = platform.system()
    if system == "Windows":
        return {
            "platform": "Windows",
            "shell": True,          # Windows needs shell=True for az.cmd
            "az_cmd": "az",
        }
    elif is_wsl():
        # In WSL, prefer native Linux az CLI; fall back to Windows az.cmd
        native_az = subprocess.run(
            ["which", "az"], capture_output=True, text=True, check=False
        )
        if native_az.returncode == 0:
            return {
                "platform": "WSL (native az)",
                "shell": False,
                "az_cmd": "az",
            }
        else:
            return {
                "platform": "WSL (Windows az)",
                "shell": False,
                "az_cmd": "az.cmd",
            }
    else:
        return {
            "platform": "Linux/macOS",
            "shell": False,
            "az_cmd": "az",
        }


# Global platform configuration, set once at import time
PLATFORM = get_platform_info()


# ══════════════════════════════════════════════════════════════
# Network / IP Detection
# Determines the user's public-facing IP address using external
# lookup services. This IP is used as the source address in NSG
# allow rules, ensuring only the user's network can connect.
# ══════════════════════════════════════════════════════════════

def get_public_ip() -> str:
    """
    Detect the user's public IP address by querying external services.
    Tries multiple services in order (ipify, ifconfig.me, checkip.amazonaws.com)
    for reliability. The first successful response is used.

    Returns:
        The detected public IP address as a string.

    Exits:
        If no service responds successfully, prints an error and exits.
    """
    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://checkip.amazonaws.com",
    ]
    for service in services:
        try:
            req = urllib.request.Request(service, headers={"User-Agent": "curl/7.68.0"})
            with urllib.request.urlopen(req, timeout=10) as response:
                ip = response.read().decode("utf-8").strip()
                print_success(f"Detected public IP: {Colors.BOLD}{ip}{Colors.RESET}")
                return ip
        except Exception:
            continue
    print_error("Failed to detect public IP address.")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════
# Azure CLI Helpers
# Wrappers around the Azure CLI (az) for executing commands,
# parsing JSON output, handling authentication token refresh,
# and retrying on token expiration.
# ══════════════════════════════════════════════════════════════

def build_command(args: list) -> list:
    """
    Build the full command list for an Azure CLI invocation.
    Prepends the platform-appropriate az binary name.

    Args:
        args: List of Azure CLI arguments (e.g., ["vm", "list"]).

    Returns:
        Complete command list (e.g., ["az", "vm", "list"]).
    """
    return [PLATFORM["az_cmd"]] + args


def run_az_command(args: list, parse_json: bool = True):
    """
    Execute an Azure CLI command and return the parsed result.

    This function:
      1. Builds the full command with the platform-specific az binary
      2. Appends "--output json" if JSON parsing is requested
      3. Runs the command via subprocess
      4. If the command fails due to expired/missing tokens, automatically
         refreshes authentication and retries once
      5. Parses the JSON output (handling cases where az CLI may output
         warnings before JSON)

    Args:
        args:       List of Azure CLI arguments.
        parse_json: If True, parse stdout as JSON and return the object.
                    If False, return raw stdout as a string.

    Returns:
        Parsed JSON object (dict/list) or raw string depending on parse_json.

    Exits:
        On unrecoverable Azure CLI errors or if az CLI is not installed.
    """
    cmd = build_command(args + (["--output", "json"] if parse_json else []))
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=False,
            shell=PLATFORM["shell"]
        )
        if result.returncode != 0:
            stderr = result.stderr.strip()
            # Check if the error is an authentication/token issue
            if "AADSTS" in stderr or "az login" in stderr or "expired" in stderr:
                print_warn("Access token expired or not found. Refreshing...")
                refresh_token()
                # Retry the command after refreshing the token
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=False,
                    shell=PLATFORM["shell"]
                )
                if result.returncode != 0:
                    print_error(f"Azure CLI command failed after refresh: {result.stderr}")
                    sys.exit(1)
            else:
                print_error(f"Azure CLI command failed: {stderr}")
                sys.exit(1)
        if parse_json and result.stdout.strip():
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                # Sometimes az CLI prints warnings/info lines before JSON.
                # Try to find the JSON object in the output.
                lines = result.stdout.strip().splitlines()
                json_start = None
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped.startswith(("{", "[")):
                        json_start = i
                        break
                if json_start is not None:
                    json_text = "\n".join(lines[json_start:])
                    return json.loads(json_text)
                print_error(f"Failed to parse JSON output: {result.stdout[:200]}")
                sys.exit(1)
        return result.stdout.strip()
    except FileNotFoundError:
        print_error(f"Azure CLI ('{PLATFORM['az_cmd']}') not found. Please install it first.")
        if is_wsl():
            print_detail("Install Azure CLI in WSL: curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash")
            print_detail("Or ensure Windows Azure CLI is accessible from WSL.")
        sys.exit(1)


def refresh_token():
    """
    Refresh the Azure CLI authentication token.

    First attempts to silently refresh the existing token via
    'az account get-access-token'. If that fails (token is completely
    expired or revoked), initiates an interactive browser login via 'az login'.

    Exits:
        If interactive login also fails, prints an error and exits.
    """
    print_info("Attempting to refresh Azure CLI token...")
    cmd = build_command(["account", "get-access-token", "--output", "json"])
    result = subprocess.run(
        cmd, capture_output=True, text=True, check=False,
        shell=PLATFORM["shell"],
    )
    if result.returncode != 0:
        print_info("Token refresh failed. Initiating interactive login...")
        login_cmd = build_command(["login"])
        login_result = subprocess.run(
            login_cmd, capture_output=False, text=True, check=False,
            shell=PLATFORM["shell"],
        )
        if login_result.returncode != 0:
            print_error("Azure login failed. Please run 'az login' manually.")
            sys.exit(1)
    print_success("Token refreshed successfully.")


def ensure_authenticated():
    """
    Ensure the user is authenticated with Azure CLI before running commands.

    Checks the current access token validity and expiration time.
    If the token expires within 5 minutes, proactively refreshes it
    to prevent mid-operation authentication failures.
    """
    print_info("Checking Azure CLI authentication...")
    cmd = build_command(["account", "get-access-token", "--output", "json"])
    result = subprocess.run(
        cmd, capture_output=True, text=True, check=False,
        shell=PLATFORM["shell"],
    )
    if result.returncode != 0:
        refresh_token()
    else:
        try:
            token_info = json.loads(result.stdout)
            from datetime import datetime, timezone
            expires_on = token_info.get("expiresOn", "")
            if expires_on:
                try:
                    exp_time = datetime.fromisoformat(expires_on.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    remaining = (exp_time - now).total_seconds()
                    if remaining < 300:
                        print_warn("Token expires soon. Refreshing...")
                        refresh_token()
                    else:
                        print_success("Authentication valid.")
                except (ValueError, TypeError):
                    print_success("Authentication valid.")
        except json.JSONDecodeError:
            refresh_token()


# ══════════════════════════════════════════════════════════════
# Azure Resource Query Functions
# Functions for retrieving VM details, network interfaces,
# NSG information, and subscription context from Azure.
# ══════════════════════════════════════════════════════════════

def get_current_subscription() -> dict:
    """
    Get the current Azure subscription context.
    Displays the subscription name and ID for user confirmation.

    Returns:
        Dict containing subscription details (name, id, etc.).
    """
    result = run_az_command(["account", "show"])
    print_info(f"Subscription: {Colors.BOLD}{result['name']}{Colors.RESET} {Colors.DIM}({result['id']}){Colors.RESET}")
    return result


def get_vm_details(resource_id: str) -> dict:
    """
    Get full VM details from an Azure resource ID.

    Args:
        resource_id: Full Azure resource ID of the VM.

    Returns:
        Dict containing all VM properties.
    """
    return run_az_command(["vm", "show", "--ids", resource_id])


def detect_vm_os(resource_id: str, port_config: Optional[dict] = None) -> dict:
    """
    Detect whether a VM is running Windows or Linux and return access configuration.

    Detection priority:
      1. OS profile (windowsConfiguration / linuxConfiguration)
      2. OS disk type (osDisk.osType)
      3. Image reference (publisher, offer, sku keywords)
      4. Default fallback to Linux if detection fails

    Args:
        resource_id: Full Azure resource ID of the VM.
        port_config: Optional dict with 'ssh_port' and 'rdp_port' overrides.

    Returns:
        Dict with keys: os_type, port, protocol, service, vm_name.
        Example: {"os_type": "Linux", "port": "22", "protocol": "Tcp",
                  "service": "SSH", "vm_name": "my-vm"}
    """
    vm = run_az_command(["vm", "show", "--ids", resource_id])
    vm_name = vm.get("name", "unknown")

    os_profile = vm.get("osProfile") or {}
    storage_profile = vm.get("storageProfile") or {}
    image_ref = storage_profile.get("imageReference") or {}
    os_disk = storage_profile.get("osDisk") or {}

    port_config = port_config or {}
    ssh_port = port_config.get("ssh_port", DEFAULT_SSH_PORT)
    rdp_port = port_config.get("rdp_port", DEFAULT_RDP_PORT)

    os_info = None

    # Strategy 1: Check osProfile configuration objects
    if os_profile.get("windowsConfiguration") is not None:
        os_info = {"os_type": "Windows", "port": rdp_port, "protocol": "Tcp", "service": "RDP", "vm_name": vm_name}
    elif os_profile.get("linuxConfiguration") is not None:
        os_info = {"os_type": "Linux", "port": ssh_port, "protocol": "Tcp", "service": "SSH", "vm_name": vm_name}

    # Strategy 2: Check osDisk.osType field
    if os_info is None:
        os_type = os_disk.get("osType", "") or ""
        if os_type.lower() == "windows":
            os_info = {"os_type": "Windows", "port": rdp_port, "protocol": "Tcp", "service": "RDP", "vm_name": vm_name}
        elif os_type.lower() == "linux":
            os_info = {"os_type": "Linux", "port": ssh_port, "protocol": "Tcp", "service": "SSH", "vm_name": vm_name}

    # Strategy 3: Check imageReference fields for Windows keywords
    if os_info is None:
        offer = (image_ref.get("offer") or "").lower()
        publisher = (image_ref.get("publisher") or "").lower()
        sku = (image_ref.get("sku") or "").lower()
        windows_keywords = ["windows", "windowsserver", "windowsdesktop", "microsoftwindows", "win"]

        if any(kw in offer for kw in windows_keywords) or \
           any(kw in publisher for kw in windows_keywords) or \
           any(kw in sku for kw in windows_keywords):
            os_info = {"os_type": "Windows", "port": rdp_port, "protocol": "Tcp", "service": "RDP", "vm_name": vm_name}

    # Strategy 4: Default to Linux if all detection methods fail
    if os_info is None:
        print_warn(f"Could not detect OS for VM '{vm_name}'. Defaulting to Linux (SSH).")
        os_info = {"os_type": "Linux", "port": ssh_port, "protocol": "Tcp", "service": "SSH", "vm_name": vm_name}

    # Log port overrides for awareness
    if os_info["service"] == "SSH" and ssh_port != DEFAULT_SSH_PORT:
        print_info(f"SSH port override: {DEFAULT_SSH_PORT} {ARROW} {Colors.BOLD}{ssh_port}{Colors.RESET}")
    elif os_info["service"] == "RDP" and rdp_port != DEFAULT_RDP_PORT:
        print_info(f"RDP port override: {DEFAULT_RDP_PORT} {ARROW} {Colors.BOLD}{rdp_port}{Colors.RESET}")

    return os_info


def get_all_vms_in_subscription() -> list:
    """
    Retrieve all virtual machines in the current Azure subscription.

    Returns:
        List of dicts, each with keys: name, id, resourceGroup.
        Returns empty list if no VMs are found.
    """
    print_info("Retrieving all VMs in current subscription...")
    result = run_az_command([
        "vm", "list", "--query",
        "[].{name:name, id:id, resourceGroup:resourceGroup}",
    ])
    if not result:
        print_warn("No VMs found in current subscription.")
        return []
    print_success(f"Found {Colors.BOLD}{len(result)}{Colors.RESET}{Colors.GREEN} VM(s) in subscription.{Colors.RESET}")
    return result


def get_vm_network_interfaces(resource_id: str) -> list:
    """
    Get all network interface (NIC) resource IDs attached to a VM.

    Args:
        resource_id: Full Azure resource ID of the VM.

    Returns:
        List of NIC resource ID strings.
    """
    vm = run_az_command(["vm", "show", "--ids", resource_id])
    nic_refs = vm.get("networkProfile", {}).get("networkInterfaces", [])
    return [nic["id"] for nic in nic_refs]


def get_vm_location(resource_id: str) -> str:
    """
    Get the Azure region (location) of a VM.

    Args:
        resource_id: Full Azure resource ID of the VM.

    Returns:
        Location string (e.g., "eastus", "westeurope").
    """
    vm = run_az_command(["vm", "show", "--ids", resource_id])
    return vm.get("location", "")


# ══════════════════════════════════════════════════════════════
# NSG Management Functions
# Functions for creating, attaching, querying, and modifying
# Network Security Groups and their rules.
# ══════════════════════════════════════════════════════════════

def create_nsg(nsg_name: str, resource_group: str, location: str) -> dict:
    """
    Create a new Network Security Group in Azure.

    Args:
        nsg_name:       Name for the new NSG.
        resource_group: Resource group to create the NSG in.
        location:       Azure region for the NSG.

    Returns:
        Dict containing the created NSG's properties.
    """
    print_info(f"Creating NSG '{Colors.BOLD}{nsg_name}{Colors.RESET}' in RG '{resource_group}' ({location})")
    result = run_az_command([
        "network", "nsg", "create",
        "--resource-group", resource_group,
        "--name", nsg_name,
        "--location", location,
    ])
    nsg = result.get("NewNSG") or result
    print_success(f"NSG '{nsg_name}' created.")
    return nsg


def attach_nsg_to_nic(nic_id: str, nsg_id: str):
    """
    Attach (associate) an NSG to a network interface.

    Args:
        nic_id: Full resource ID of the NIC.
        nsg_id: Full resource ID of the NSG.
    """
    parts = nic_id.split("/")
    rg_idx = parts.index("resourceGroups") + 1
    nic_name = parts[-1]
    resource_group = parts[rg_idx]

    print_info(f"Attaching NSG to NIC '{Colors.BOLD}{nic_name}{Colors.RESET}'")
    run_az_command([
        "network", "nic", "update",
        "--resource-group", resource_group,
        "--name", nic_name,
        "--network-security-group", nsg_id,
    ])
    print_success(f"NSG attached to NIC '{nic_name}'.")


def attach_nsg_to_subnet(subnet_id: str, nsg_id: str):
    """
    Attach (associate) an NSG to a subnet.

    Args:
        subnet_id: Full resource ID of the subnet.
        nsg_id:    Full resource ID of the NSG.
    """
    parts = subnet_id.split("/")
    rg_idx = parts.index("resourceGroups") + 1
    vnet_idx = parts.index("virtualNetworks") + 1
    subnet_idx = parts.index("subnets") + 1
    resource_group = parts[rg_idx]
    vnet_name = parts[vnet_idx]
    subnet_name = parts[subnet_idx]

    print_info(f"Attaching NSG to subnet '{Colors.BOLD}{subnet_name}{Colors.RESET}' in VNet '{vnet_name}'")
    run_az_command([
        "network", "vnet", "subnet", "update",
        "--resource-group", resource_group,
        "--vnet-name", vnet_name,
        "--name", subnet_name,
        "--network-security-group", nsg_id,
    ])
    print_success(f"NSG attached to subnet '{subnet_name}'.")


def get_nsg_from_nic(nic_id: str, vm_name: str, location: str) -> list:
    """
    Get all NSGs associated with a NIC (both NIC-level and subnet-level).
    If no NSG is found on either the NIC or its subnets, auto-creates new NSGs.

    The function checks:
      1. NIC-level NSG: Directly attached to the network interface
      2. Subnet-level NSG: Attached to the subnet(s) the NIC belongs to

    If either level is missing an NSG, a new one is created and attached
    automatically to ensure the VM has proper network security.

    Args:
        nic_id:   Full resource ID of the NIC.
        vm_name:  VM name (used for naming auto-created NSGs).
        location: Azure region (used for creating NSGs in the same region).

    Returns:
        List of dicts, each with keys: id, source ("NIC", "Subnet", etc.).
    """
    nsgs = []
    nic = run_az_command(["network", "nic", "show", "--ids", nic_id])
    nic_name = nic.get("name", "")
    nic_rg_parts = nic_id.split("/")
    nic_rg_idx = nic_rg_parts.index("resourceGroups") + 1
    nic_resource_group = nic_rg_parts[nic_rg_idx]

    nic_has_nsg = False
    subnet_has_nsg = False

    # Check for NIC-level NSG
    nic_nsg = nic.get("networkSecurityGroup")
    if nic_nsg:
        nic_has_nsg = True
        nsgs.append({"id": nic_nsg["id"], "source": "NIC", "nic_name": nic_name})

    # Check for subnet-level NSGs on all IP configurations
    ip_configs = nic.get("ipConfigurations", [])
    subnet_ids_checked = []
    for ip_config in ip_configs:
        subnet = ip_config.get("subnet")
        if subnet:
            subnet_id = subnet["id"]
            if subnet_id in subnet_ids_checked:
                continue
            subnet_ids_checked.append(subnet_id)

            parts = subnet_id.split("/")
            rg_idx = parts.index("resourceGroups") + 1
            vnet_idx = parts.index("virtualNetworks") + 1
            subnet_idx = parts.index("subnets") + 1

            subnet_info = run_az_command([
                "network", "vnet", "subnet", "show",
                "--resource-group", parts[rg_idx],
                "--vnet-name", parts[vnet_idx],
                "--name", parts[subnet_idx],
            ])
            subnet_nsg = subnet_info.get("networkSecurityGroup")
            if subnet_nsg:
                subnet_has_nsg = True
                if not any(n["id"] == subnet_nsg["id"] for n in nsgs):
                    nsgs.append({"id": subnet_nsg["id"], "source": "Subnet", "subnet_name": parts[subnet_idx]})
            else:
                subnet_name = parts[subnet_idx]
                print_warn(f"No NSG found on subnet '{subnet_name}'. Auto-creating...")
                timestamp = int(time.time())
                new_nsg_name = f"nsg-{subnet_name}-subnet-{timestamp}"
                new_nsg = create_nsg(new_nsg_name, parts[rg_idx], location)
                new_nsg_id = new_nsg.get("id", "")
                if not new_nsg_id:
                    fetched_nsg = run_az_command([
                        "network", "nsg", "show",
                        "--resource-group", parts[rg_idx],
                        "--name", new_nsg_name,
                    ])
                    new_nsg_id = fetched_nsg.get("id", "")
                if new_nsg_id:
                    attach_nsg_to_subnet(subnet_id, new_nsg_id)
                    if not any(n["id"] == new_nsg_id for n in nsgs):
                        nsgs.append({"id": new_nsg_id, "source": "Subnet (auto-created)", "subnet_name": subnet_name})
                else:
                    print_error("Failed to retrieve NSG ID after creation.")

    # Auto-create NIC-level NSG if none exists
    if not nic_has_nsg:
        print_warn(f"No NSG found on NIC '{nic_name}'. Auto-creating...")
        timestamp = int(time.time())
        new_nsg_name = f"nsg-{vm_name}-nic-{timestamp}"
        new_nsg = create_nsg(new_nsg_name, nic_resource_group, location)
        new_nsg_id = new_nsg.get("id", "")
        if not new_nsg_id:
            fetched_nsg = run_az_command([
                "network", "nsg", "show",
                "--resource-group", nic_resource_group,
                "--name", new_nsg_name,
            ])
            new_nsg_id = fetched_nsg.get("id", "")
        if new_nsg_id:
            attach_nsg_to_nic(nic_id, new_nsg_id)
            nsgs.append({"id": new_nsg_id, "source": "NIC (auto-created)", "nic_name": nic_name})
        else:
            print_error("Failed to retrieve NSG ID after creation.")

    return nsgs


def get_existing_rules(nsg_name: str, resource_group: str) -> list:
    """
    Get all existing security rules in an NSG.
    Note: This returns only custom rules, not the default Azure rules
    (which have priorities >= 65000).

    Args:
        nsg_name:       Name of the NSG.
        resource_group: Resource group containing the NSG.

    Returns:
        List of rule dicts, or empty list if no rules exist.
    """
    rules = run_az_command([
        "network", "nsg", "rule", "list",
        "--nsg-name", nsg_name,
        "--resource-group", resource_group,
    ])
    return rules if rules else []


def find_available_priority(existing_rules: list, start: int = 100, end: int = 4096) -> int:
    """
    Find the next available (unused) priority number for a new NSG rule.
    Priorities must be unique within an NSG and range from 100-4096 for custom rules.

    Args:
        existing_rules: List of existing rule dicts (each with a 'priority' field).
        start:          Minimum priority to consider (default: 100).
        end:            Maximum priority to consider (default: 4096).

    Returns:
        An available priority number.

    Exits:
        If no priority is available in the range (extremely unlikely).
    """
    used_priorities = {rule.get("priority", 0) for rule in existing_rules}
    for priority in range(start, end):
        if priority not in used_priorities:
            return priority
    print_error("No available priority found for NSG rule.")
    sys.exit(1)


def get_rule_signature(rule: dict) -> tuple:
    """
    Generate a unique signature tuple for a rule to identify duplicates.
    Two rules with the same signature are considered functionally identical
    (same direction, access, protocol, source, and destination).

    Args:
        rule: An NSG rule dict.

    Returns:
        A tuple of lowercased rule fields for comparison.
    """
    return (
        rule.get("direction", "").lower(),
        rule.get("access", "").lower(),
        rule.get("protocol", "").lower(),
        rule.get("sourceAddressPrefix", "").lower(),
        rule.get("sourcePortRange", "").lower(),
        rule.get("destinationAddressPrefix", "").lower(),
        rule.get("destinationPortRange", "").lower(),
    )


def find_duplicate_rules(existing_rules: list) -> list:
    """
    Find all duplicate NSG rules based on their functional signature.
    When duplicates are found, the rule with the lowest priority number
    (highest precedence) is kept, and the others are marked for removal.

    Args:
        existing_rules: List of NSG rule dicts.

    Returns:
        List of dicts describing duplicates to remove, each with:
        name, priority, kept_name, kept_priority.
    """
    signature_map = {}
    for rule in existing_rules:
        sig = get_rule_signature(rule)
        if sig not in signature_map:
            signature_map[sig] = []
        signature_map[sig].append(rule)

    duplicates_to_remove = []
    for sig, rules in signature_map.items():
        if len(rules) > 1:
            # Keep the rule with the lowest priority (highest precedence)
            rules_sorted = sorted(rules, key=lambda r: r.get("priority", 9999))
            kept = rules_sorted[0]
            for dup in rules_sorted[1:]:
                duplicates_to_remove.append({
                    "name": dup.get("name"),
                    "priority": dup.get("priority"),
                    "kept_name": kept.get("name"),
                    "kept_priority": kept.get("priority"),
                })
    return duplicates_to_remove


def remove_duplicate_rules(nsg_name: str, resource_group: str):
    """
    Find and remove duplicate security rules in a given NSG.
    Duplicates are identified by comparing the functional signature of each rule.
    Only the highest-priority (lowest number) instance is kept.

    Args:
        nsg_name:       Name of the NSG to check.
        resource_group: Resource group containing the NSG.
    """
    existing_rules = get_existing_rules(nsg_name, resource_group)
    if not existing_rules:
        return

    duplicates = find_duplicate_rules(existing_rules)
    if not duplicates:
        print_info(f"No duplicate rules in NSG '{Colors.BOLD}{nsg_name}{Colors.RESET}'")
        return

    print_warn(f"Found {Colors.BOLD}{len(duplicates)}{Colors.RESET}{Colors.YELLOW} duplicate rule(s) in '{nsg_name}':{Colors.RESET}")
    for dup in duplicates:
        print_detail(f"{CROSS} '{dup['name']}' (pri {dup['priority']}) "
                     f"← dup of '{dup['kept_name']}' (pri {dup['kept_priority']})")

    for dup in duplicates:
        run_az_command([
            "network", "nsg", "rule", "delete",
            "--resource-group", resource_group,
            "--nsg-name", nsg_name,
            "--name", dup["name"],
        ], parse_json=False)

    print_success(f"Removed {len(duplicates)} duplicate rule(s) from '{nsg_name}'.")


# ══════════════════════════════════════════════════════════════
# Rule Matching Helpers
# Functions for checking if existing NSG rules already cover
# the desired access (matching source IP, port, and direction).
# This prevents adding redundant rules.
# ══════════════════════════════════════════════════════════════

def port_matches(rule_port: str, target_port: str) -> bool:
    """
    Check if an NSG rule's destination port specification covers a target port.
    Handles wildcards ("*"), exact matches, and port ranges ("1000-2000").

    Args:
        rule_port:   The port specification from the NSG rule.
        target_port: The specific port to check coverage for.

    Returns:
        True if the rule's port covers the target port.
    """
    if not rule_port:
        return False
    rule_port = rule_port.strip()
    if rule_port == "*":
        return True
    if rule_port == target_port:
        return True
    if "-" in rule_port:
        try:
            low, high = rule_port.split("-", 1)
            if int(low) <= int(target_port) <= int(high):
                return True
        except (ValueError, TypeError):
            pass
    return False


def source_matches(rule_source: str, source_ip: str) -> bool:
    """
    Check if an NSG rule's source address specification covers a given IP.
    Handles wildcards ("*", "Internet", "Any"), exact IP matches,
    CIDR /32 notation, and CIDR subnet matching (e.g., "10.0.0.0/24").

    Args:
        rule_source: The source address prefix from the NSG rule.
        source_ip:   The specific IP address to check coverage for.

    Returns:
        True if the rule's source covers the given IP.
    """
    if not rule_source:
        return False
    rule_source = rule_source.strip()
    # Check wildcard/special values
    if rule_source in ("*", "Internet", "Any"):
        return True
    # Check exact IP match
    if rule_source == source_ip:
        return True
    # Check /32 CIDR notation (exact IP in CIDR form)
    if rule_source == f"{source_ip}/32":
        return True
    # Check CIDR subnet match
    if "/" in rule_source:
        try:
            import ipaddress
            network = ipaddress.ip_network(rule_source, strict=False)
            ip = ipaddress.ip_address(source_ip)
            if ip in network:
                return True
        except (ValueError, TypeError):
            pass
    return False


def check_existing_allow_rule(existing_rules: list, source_ip: str, port: str) -> Optional[dict]:
    """
    Check if any existing NSG rule already allows the required inbound TCP access.

    Evaluates rules in priority order (lowest number = highest priority).
    For each rule that matches the source IP and destination port:
      - If it's an "Allow" rule, returns it (access is already granted)
      - If it's a "Deny" rule, returns None (access is explicitly blocked
        by a higher-priority deny rule)

    This prevents adding redundant allow rules when access is already permitted,
    and avoids adding rules that would be overridden by a deny.

    Args:
        existing_rules: List of NSG rule dicts.
        source_ip:      The source IP address to check.
        port:           The destination port to check.

    Returns:
        The matching allow rule dict if access is already granted, or None.
    """
    sorted_rules = sorted(existing_rules, key=lambda r: r.get("priority", 9999))

    for rule in sorted_rules:
        direction = (rule.get("direction") or "").lower()
        access = (rule.get("access") or "").lower()
        protocol = (rule.get("protocol") or "").lower()

        # Only check inbound TCP (or wildcard protocol) rules
        if direction != "inbound":
            continue
        if protocol not in ("tcp", "*"):
            continue

        # Check source address match (single prefix or list of prefixes)
        rule_source = rule.get("sourceAddressPrefix", "")
        source_prefixes = rule.get("sourceAddressPrefixes") or []
        source_matched = source_matches(rule_source, source_ip)
        if not source_matched:
            for prefix in source_prefixes:
                if source_matches(prefix, source_ip):
                    source_matched = True
                    break
        if not source_matched:
            continue

        # Check destination port match (single port or list of ports/ranges)
        rule_port = rule.get("destinationPortRange", "")
        dest_port_ranges = rule.get("destinationPortRanges") or []
        port_matched = port_matches(rule_port, port)
        if not port_matched:
            for port_range in dest_port_ranges:
                if port_matches(port_range, port):
                    port_matched = True
                    break
        if not port_matched:
            continue

        # At this point, the rule matches source and port.
        # If it's Allow, access is already granted. If Deny, it's blocked.
        if access == "allow":
            return rule
        elif access == "deny":
            return None

    return None


def add_access_rule_to_nsg(nsg_id: str, source_ip: str, os_info: dict):
    """
    Add an SSH or RDP allow rule to an NSG based on the VM's detected OS type.

    Before adding:
      1. Removes any duplicate rules in the NSG
      2. Checks if an existing rule already allows the required access
      3. Only creates a new rule if one is actually needed

    The rule is named with a descriptive format including the service type,
    sanitized source IP, and Unix timestamp for uniqueness.
    Example: "Allow-SSH-203-0-113-50-1706300000"

    Args:
        nsg_id:    Full resource ID of the NSG to modify.
        source_ip: The source IP address to allow.
        os_info:   Dict from detect_vm_os() with service/port information.
    """
    parts = nsg_id.split("/")
    rg_idx = parts.index("resourceGroups") + 1
    nsg_idx = parts.index("networkSecurityGroups") + 1
    resource_group = parts[rg_idx]
    nsg_name = parts[nsg_idx]

    port = os_info["port"]
    service = os_info["service"]
    os_type = os_info["os_type"]
    vm_name = os_info.get("vm_name", "unknown")

    print_subsection(f"NSG: {nsg_name}")
    print_key_value("Resource Group", resource_group)
    print_key_value("Action", f"Open {service} port {port} for {os_type} VM '{vm_name}'")

    # Step 1: Clean up any duplicate rules
    remove_duplicate_rules(nsg_name, resource_group)

    # Step 2: Check if access is already allowed by an existing rule
    existing_rules = get_existing_rules(nsg_name, resource_group)
    matching_rule = check_existing_allow_rule(existing_rules, source_ip, port)
    if matching_rule:
        rule_name = matching_rule.get("name", "unknown")
        rule_priority = matching_rule.get("priority", "?")
        rule_source = matching_rule.get("sourceAddressPrefix", "")
        rule_port = matching_rule.get("destinationPortRange", "")
        source_prefixes = matching_rule.get("sourceAddressPrefixes") or []
        dest_port_ranges = matching_rule.get("destinationPortRanges") or []

        display_source = rule_source or ", ".join(source_prefixes) or "?"
        display_port = rule_port or ", ".join(dest_port_ranges) or "?"

        print_skip(f"{service} access already allowed by existing rule:")
        print_detail(f"Rule: '{rule_name}' (priority {rule_priority})")
        print_detail(f"Source: {display_source} {ARROW} Port: {display_port}")
        return

    # Step 3: Create a new allow rule
    priority = find_available_priority(existing_rules)
    timestamp = int(time.time())
    ip_sanitized = source_ip.replace(".", "-")
    rule_name = f"Allow-{service}-{ip_sanitized}-{timestamp}"

    print_info(f"Adding rule '{Colors.BOLD}{rule_name}{Colors.RESET}'")
    print_detail(f"Priority: {priority}  |  Source: {source_ip}/32  |  Port: {port}")

    run_az_command([
        "network", "nsg", "rule", "create",
        "--resource-group", resource_group,
        "--nsg-name", nsg_name,
        "--name", rule_name,
        "--priority", str(priority),
        "--direction", "Inbound",
        "--access", "Allow",
        "--protocol", "Tcp",
        "--source-address-prefixes", f"{source_ip}/32",
        "--source-port-ranges", "*",
        "--destination-address-prefixes", "*",
        "--destination-port-ranges", port,
        "--description", f"Allow {service} from {source_ip} to {os_type} VM '{vm_name}' (port {port}) - auto-added",
    ])

    print_success(f"{service} rule added to '{nsg_name}' for {source_ip}:{port}")


# ══════════════════════════════════════════════════════════════
# Remove All Custom Rules
# Functions for removing all custom (user-defined) security rules
# from NSGs associated with VMs. This is useful for cleaning up
# when access is no longer needed or before re-provisioning rules.
# Default Azure rules (priority >= 65000) are never removed.
# ══════════════════════════════════════════════════════════════

def remove_all_rules_from_nsg(nsg_id: str):
    """
    Remove ALL custom security rules from an NSG.
    Default Azure rules (DenyAllInBound, AllowVnetInBound, etc.) with
    priorities >= 65000 are never deleted — they are managed by Azure
    and cannot be removed.

    Args:
        nsg_id: Full resource ID of the NSG.
    """
    parts = nsg_id.split("/")
    rg_idx = parts.index("resourceGroups") + 1
    nsg_idx = parts.index("networkSecurityGroups") + 1
    resource_group = parts[rg_idx]
    nsg_name = parts[nsg_idx]

    print_subsection(f"NSG: {nsg_name}")
    print_key_value("Resource Group", resource_group)

    # Get all custom rules
    existing_rules = get_existing_rules(nsg_name, resource_group)

    if not existing_rules:
        print_info(f"No custom rules found in NSG '{Colors.BOLD}{nsg_name}{Colors.RESET}'. Nothing to remove.")
        return

    # Display rules that will be removed
    print_warn(f"Found {Colors.BOLD}{len(existing_rules)}{Colors.RESET}{Colors.YELLOW} custom rule(s) to remove:{Colors.RESET}")
    for rule in existing_rules:
        rule_name = rule.get("name", "unknown")
        priority = rule.get("priority", "?")
        direction = rule.get("direction", "?")
        access = rule.get("access", "?")
        source = rule.get("sourceAddressPrefix", "") or ", ".join(rule.get("sourceAddressPrefixes", []) or []) or "*"
        dest_port = rule.get("destinationPortRange", "") or ", ".join(rule.get("destinationPortRanges", []) or []) or "*"

        # Color-code access type for readability
        access_color = Colors.GREEN if access.lower() == "allow" else Colors.RED
        print_detail(f"{CROSS} '{rule_name}' | pri:{priority} | {direction} | "
                     f"{access_color}{access}{Colors.RESET}{Colors.DIM} | "
                     f"src:{source} | port:{dest_port}{Colors.RESET}")

    # Delete each rule
    removed_count = 0
    for rule in existing_rules:
        rule_name = rule.get("name", "")
        if not rule_name:
            continue
        run_az_command([
            "network", "nsg", "rule", "delete",
            "--resource-group", resource_group,
            "--nsg-name", nsg_name,
            "--name", rule_name,
        ], parse_json=False)
        removed_count += 1

    print_success(f"Removed {removed_count} custom rule(s) from '{nsg_name}'.")


def get_all_nsgs_for_vm(resource_id: str) -> list:
    """
    Get all unique NSGs associated with a VM (both NIC-level and subnet-level).
    Unlike get_nsg_from_nic(), this function does NOT auto-create any NSGs.
    It is used for read-only operations like cleanup and rule removal.

    Args:
        resource_id: Full Azure resource ID of the VM.

    Returns:
        List of dicts, each with keys: id, source, name, resource_group.
    """
    nsgs = []
    nic_ids = get_vm_network_interfaces(resource_id)

    for nic_id in nic_ids:
        nic = run_az_command(["network", "nic", "show", "--ids", nic_id])
        nic_name = nic.get("name", "")

        # Check NIC-level NSG
        nic_nsg = nic.get("networkSecurityGroup")
        if nic_nsg:
            nsg_id = nic_nsg["id"]
            if not any(n["id"] == nsg_id for n in nsgs):
                parts = nsg_id.split("/")
                rg_idx = parts.index("resourceGroups") + 1
                nsg_name_idx = parts.index("networkSecurityGroups") + 1
                nsgs.append({
                    "id": nsg_id,
                    "source": f"NIC ({nic_name})",
                    "name": parts[nsg_name_idx],
                    "resource_group": parts[rg_idx],
                })

        # Check subnet-level NSGs
        ip_configs = nic.get("ipConfigurations", [])
        checked_subnets = set()
        for ip_config in ip_configs:
            subnet = ip_config.get("subnet")
            if subnet:
                subnet_id = subnet["id"]
                if subnet_id in checked_subnets:
                    continue
                checked_subnets.add(subnet_id)

                parts = subnet_id.split("/")
                rg_idx = parts.index("resourceGroups") + 1
                vnet_idx = parts.index("virtualNetworks") + 1
                subnet_idx = parts.index("subnets") + 1

                subnet_info = run_az_command([
                    "network", "vnet", "subnet", "show",
                    "--resource-group", parts[rg_idx],
                    "--vnet-name", parts[vnet_idx],
                    "--name", parts[subnet_idx],
                ])
                subnet_nsg = subnet_info.get("networkSecurityGroup")
                if subnet_nsg:
                    nsg_id = subnet_nsg["id"]
                    if not any(n["id"] == nsg_id for n in nsgs):
                        nsg_parts = nsg_id.split("/")
                        nsg_rg_idx = nsg_parts.index("resourceGroups") + 1
                        nsg_name_idx = nsg_parts.index("networkSecurityGroups") + 1
                        nsgs.append({
                            "id": nsg_id,
                            "source": f"Subnet ({parts[subnet_idx]})",
                            "name": nsg_parts[nsg_name_idx],
                            "resource_group": nsg_parts[nsg_rg_idx],
                        })

    return nsgs


def remove_all_rules_for_vm(resource_id: str):
    """
    Remove all custom security rules from ALL NSGs associated with a VM.
    Scans both NIC-level and subnet-level NSGs.

    Args:
        resource_id: Full Azure resource ID of the VM.
    """
    vm_name = resource_id.split("/")[-1] if "/" in resource_id else resource_id
    print_vm_processing_header(vm_name)

    nsgs = get_all_nsgs_for_vm(resource_id)
    if not nsgs:
        print_warn(f"No NSGs found for VM '{vm_name}'.")
        return

    print_info(f"Found {Colors.BOLD}{len(nsgs)}{Colors.RESET} NSG(s) associated with VM '{vm_name}':")
    for nsg in nsgs:
        print_bullet(f"{nsg['name']} {Colors.DIM}(via {nsg['source']}){Colors.RESET}")

    print()
    for nsg in nsgs:
        remove_all_rules_from_nsg(nsg["id"])


def remove_rules_interactive():
    """
    Interactive mode for removing all custom security rules from VMs.
    Displays a VM selection table and asks for confirmation before deleting.
    No NSG rules are modified without explicit user consent.
    """
    print_section("Remove All Custom Rules", TRASH_ICON)
    print_warn("This will remove ALL custom security rules from the selected VMs' NSGs.")
    print_detail("Default Azure rules (DenyAllInBound, AllowVnetInBound, etc.) are never removed.")
    print()

    vms = get_all_vms_in_subscription()
    if not vms:
        print_warn("No VMs found in current subscription. Exiting.")
        sys.exit(0)

    # Display VM table
    print_section("Available Virtual Machines", SERVER_ICON)
    display_vm_table(vms)

    # Select VMs
    selected_vms = select_vms_interactive(vms, action_label="Remove all custom rules")

    # Final confirmation with explicit warning
    print()
    print_box([
        f"{WARN_ICON} WARNING: This action will delete ALL custom NSG rules",
        f"  for the selected {len(selected_vms)} VM(s).",
        f"",
        f"  This includes SSH/RDP allow rules, custom deny rules,",
        f"  and any other manually or auto-created security rules.",
        f"",
        f"  Default Azure rules will NOT be affected.",
    ], color=Colors.RED)
    print()

    confirm = styled_input(f"Type 'DELETE' to confirm rule removal: ").strip()
    if confirm != "DELETE":
        print_info("Operation cancelled. No rules were modified.")
        return

    # Remove rules from all selected VMs
    print_section("Removing Rules", TRASH_ICON)
    for idx, vm in enumerate(selected_vms, 1):
        remove_all_rules_for_vm(vm["id"])

    print_completion_banner("All custom rules removed successfully")


# ══════════════════════════════════════════════════════════════
# TCP Connectivity Test Functions
# Functions for testing network connectivity to VMs after NSG
# rules have been configured. Includes VM power state detection,
# public IP resolution, and TCP handshake testing.
# ══════════════════════════════════════════════════════════════

def get_vm_power_state(resource_id: str) -> dict:
    """
    Get the power state and provisioning state of a VM.
    Uses the instance view API to get real-time status.

    Possible power states include:
      - "VM running"      → VM is powered on and operational
      - "VM stopped"      → VM is stopped but still allocated (billing continues)
      - "VM deallocated"  → VM is stopped and deallocated (no billing for compute)
      - "VM starting"     → VM is in the process of starting

    Args:
        resource_id: Full Azure resource ID of the VM.

    Returns:
        Dict with keys: power_state (str), provisioning_state (str), is_running (bool).
    """
    result = run_az_command([
        "vm", "get-instance-view", "--ids", resource_id,
        "--query", "{powerState: instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus | [0], provisioningState: provisioningState}",
    ])
    power_state = result.get("powerState", "Unknown") or "Unknown"
    provisioning_state = result.get("provisioningState", "Unknown") or "Unknown"
    return {
        "power_state": power_state,
        "provisioning_state": provisioning_state,
        "is_running": power_state == "VM running",
    }


def get_vm_public_ip_from_primary_nic(resource_id: str) -> Optional[str]:
    """
    Get the public IP address from the VM's primary NIC.

    Resolution strategy:
      1. Query all NICs attached to the VM
      2. For each NIC, check all IP configurations for a public IP reference
      3. Resolve the public IP resource to get the actual IP address
      4. If direct resolution fails, fall back to 'az vm list-ip-addresses'

    Handles edge cases:
      - VMs with no public IP (returns None)
      - VMs with dynamic IPs that may be empty when deallocated
      - Multiple NICs (checks all, not just primary)
      - API response field name variations (ipAddress vs IpAddress)

    Args:
        resource_id: Full Azure resource ID of the VM.

    Returns:
        The public IP address string, or None if not found.
    """
    # Get all NIC IDs attached to the VM
    public_ip_ids = run_az_command([
        "vm", "show", "--ids", resource_id,
        "--query", "networkProfile.networkInterfaces[].id",
    ])

    if not public_ip_ids:
        print_detail("No network interfaces found on VM.")
        return None

    # Iterate through NICs and their IP configurations
    for nic_id in public_ip_ids:
        nic = run_az_command([
            "network", "nic", "show", "--ids", nic_id,
        ])

        nic_name = nic.get("name", "unknown")
        is_primary_nic = nic.get("primary", False) or len(public_ip_ids) == 1

        ip_configs = nic.get("ipConfigurations", [])
        if not ip_configs:
            continue

        for ip_config in ip_configs:
            ip_config_name = ip_config.get("name", "")
            is_primary_config = ip_config.get("primary", False) or len(ip_configs) == 1

            public_ip_ref = ip_config.get("publicIpAddress")
            if not public_ip_ref:
                continue

            # Handle potential field name variations in the API response
            public_ip_id = public_ip_ref.get("id") or public_ip_ref.get("Id") or ""
            if not public_ip_id:
                continue

            # Resolve the public IP resource to get the actual address
            try:
                public_ip_resource = run_az_command([
                    "network", "public-ip", "show", "--ids", public_ip_id,
                ])
            except SystemExit:
                print_detail(f"Failed to query public IP resource for NIC '{nic_name}'.")
                continue

            ip_address = public_ip_resource.get("ipAddress") or public_ip_resource.get("IpAddress") or ""

            if ip_address and ip_address.lower() not in ("none", ""):
                nic_label = f"primary NIC '{nic_name}'" if is_primary_nic else f"NIC '{nic_name}'"
                config_label = f"primary config '{ip_config_name}'" if is_primary_config else f"config '{ip_config_name}'"
                print_detail(f"Public IP found on {nic_label}, {config_label}.")
                return ip_address
            else:
                # IP resource exists but has no address assigned
                # This typically happens with dynamic allocation when VM is deallocated
                alloc_method = public_ip_resource.get("publicIpAllocationMethod", "Unknown")
                print_detail(f"Public IP resource exists on NIC '{nic_name}' but address is empty "
                             f"(allocation: {alloc_method}, VM may be deallocated).")

    # Fallback: use 'az vm list-ip-addresses' which aggregates IP info reliably
    print_detail("Falling back to 'az vm list-ip-addresses'...")
    try:
        ip_list = run_az_command([
            "vm", "list-ip-addresses", "--ids", resource_id,
            "--query", "[0].virtualMachine.network.publicIpAddresses[0].ipAddress",
        ])
        if ip_list and isinstance(ip_list, str) and ip_list.lower() not in ("none", "null", ""):
            print_detail(f"Public IP resolved via fallback method.")
            return ip_list
    except SystemExit:
        pass

    print_detail("No public IP address could be resolved for this VM.")
    return None


def test_tcp_handshake(host: str, port: int, timeout: int = 5) -> dict:
    """
    Test TCP connectivity to a host:port via a three-way handshake.
    Uses a raw socket connect to verify that:
      1. DNS resolution works (for hostnames)
      2. The target is reachable
      3. The port is open and accepting connections

    Works on both Windows and WSL/Linux environments.

    Args:
        host:    Target hostname or IP address.
        port:    Target port number.
        timeout: Connection timeout in seconds (default: 5).

    Returns:
        Dict with keys:
          - success (bool): Whether the handshake completed
          - message (str): Human-readable result description
          - latency_ms (float|None): Round-trip time in milliseconds
          - host (str): The target host
          - port (int): The target port
    """
    result = {
        "success": False,
        "message": "",
        "latency_ms": None,
        "host": host,
        "port": port,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Measure connection time (includes TCP handshake)
        start_time = time.monotonic()
        error_code = sock.connect_ex((host, port))
        end_time = time.monotonic()

        latency_ms = round((end_time - start_time) * 1000, 1)
        result["latency_ms"] = latency_ms

        if error_code == 0:
            # Connection successful — port is open
            result["success"] = True
            result["message"] = f"TCP handshake succeeded ({latency_ms}ms)"
        else:
            # Connection failed — map OS error codes to human-readable messages
            error_messages = {
                # Windows error codes
                10061: "Connection refused",
                10060: "Connection timed out",
                10065: "No route to host",
                10064: "Host is down",
                10051: "Network unreachable",
                # Linux error codes
                111: "Connection refused",
                110: "Connection timed out",
                113: "No route to host",
                112: "Host is down",
                101: "Network unreachable",
            }
            error_msg = error_messages.get(error_code, f"Error code {error_code}")
            result["message"] = f"{error_msg} ({latency_ms}ms)"

        sock.close()

    except socket.timeout:
        result["message"] = f"Connection timed out after {timeout}s"
    except socket.gaierror as e:
        result["message"] = f"DNS resolution failed: {e}"
    except OSError as e:
        result["message"] = f"Socket error: {e}"
    except Exception as e:
        result["message"] = f"Unexpected error: {e}"

    return result


def run_connectivity_test(resource_id: str, os_info: dict):
    """
    Run a comprehensive connectivity test against a VM.

    Test sequence:
      1. Check VM power state (running/stopped/deallocated)
      2. If not running, display status with helpful remediation commands
      3. Resolve the VM's public IP from its primary NIC
      4. Perform TCP handshake test on the service port (SSH/RDP)
      5. Display results with latency and troubleshooting hints

    Args:
        resource_id: Full Azure resource ID of the VM.
        os_info:     Dict from detect_vm_os() with service/port/vm_name.
    """
    service = os_info["service"]
    port = int(os_info["port"])
    vm_name = os_info.get("vm_name", "unknown")

    print_subsection(f"Connectivity Test: {vm_name}")

    # Step 1: Check VM power state before attempting network tests
    print_info(f"Checking power state for '{Colors.BOLD}{vm_name}{Colors.RESET}'...")
    power_info = get_vm_power_state(resource_id)
    power_state = power_info["power_state"]
    is_running = power_info["is_running"]

    if is_running:
        print_success(f"VM status: {Colors.BOLD}{power_state}{Colors.RESET}")
    else:
        # VM is not running — show status and skip TCP test
        state_color = Colors.RED if "deallocated" in power_state.lower() or "stopped" in power_state.lower() else Colors.YELLOW
        print_warn(f"VM status: {state_color}{Colors.BOLD}{power_state}{Colors.RESET}")
        print_detail(f"Provisioning state: {power_info['provisioning_state']}")
        print_detail(f"TCP connectivity test skipped — VM is not running.")

        # Provide helpful Azure CLI commands based on the VM's state
        start_cmd = f"az vm start --ids {resource_id}"
        if "deallocated" in power_state.lower():
            print_box([
                f"VM '{vm_name}' is deallocated.",
                f"Start the VM to test connectivity.",
            ], color=Colors.YELLOW)
            print()
            print_info("To start the VM, run:")
            print(f"  {Colors.CYAN}{start_cmd}{Colors.RESET}")
            print()

            # Ask user if they want to start the VM now
            answer = input(f"  {Colors.YELLOW}{ARROW} Do you want to start the VM now? (y/N): {Colors.RESET}").strip().lower()
            if answer in ("y", "yes"):
                print_info(f"Starting VM '{vm_name}'... (this may take a few minutes)")
                result = run_az_command(["vm", "start", "--ids", resource_id], parse_json=False)
                if result is not None:
                    print_success(f"VM '{vm_name}' started successfully.")
                    # Re-check power state and continue with connectivity test
                    print_info("Waiting for VM to be ready...")
                    time.sleep(10)
                    # Recursively call to run the test now that VM is started
                    run_connectivity_test(resource_id, os_info)
                else:
                    print_error(f"Failed to start VM '{vm_name}'. Please start it manually.")
            return

        elif "stopped" in power_state.lower():
            print_box([
                f"VM '{vm_name}' is stopped (still billing).",
                f"Deallocate to stop billing, or start to use.",
            ], color=Colors.YELLOW)
            print()
            print_info("To start the VM, run:")
            print(f"  {Colors.CYAN}{start_cmd}{Colors.RESET}")
            print_info("To deallocate (stop billing), run:")
            print(f"  {Colors.CYAN}az vm deallocate --ids {resource_id}{Colors.RESET}")
            print()

            # Ask user if they want to start the VM now
            answer = input(f"  {Colors.YELLOW}{ARROW} Do you want to start the VM now? (y/N): {Colors.RESET}").strip().lower()
            if answer in ("y", "yes"):
                print_info(f"Starting VM '{vm_name}'... (this may take a few minutes)")
                result = run_az_command(["vm", "start", "--ids", resource_id], parse_json=False)
                if result is not None:
                    print_success(f"VM '{vm_name}' started successfully.")
                    print_info("Waiting for VM to be ready...")
                    time.sleep(10)
                    run_connectivity_test(resource_id, os_info)
                else:
                    print_error(f"Failed to start VM '{vm_name}'. Please start it manually.")
            return

    # Step 2: Resolve public IP from primary NIC
    print_info(f"Resolving public IP from primary NIC...")
    public_ip = get_vm_public_ip_from_primary_nic(resource_id)

    if not public_ip:
        print_warn(f"No public IP found on primary NIC for VM '{vm_name}'. Skipping connectivity test.")
        print_box([
            "Possible reasons:",
            f"  {BULLET} VM has no public IP assigned",
            f"  {BULLET} VM is behind a load balancer or NAT gateway",
            f"  {BULLET} Public IP uses dynamic allocation and VM was recently restarted",
        ], color=Colors.YELLOW)
        return

    # Step 3: Run TCP handshake test
    print_info(f"Target: {Colors.BOLD}{public_ip}:{port}{Colors.RESET} ({service})")
    print_info(f"Testing TCP handshake...")

    result = test_tcp_handshake(public_ip, port)

    if result["success"]:
        # Connection succeeded — display latency with color-coded quality indicator
        latency = result["latency_ms"]
        if latency < 50:
            latency_color = Colors.GREEN   # Good latency
        elif latency < 150:
            latency_color = Colors.YELLOW  # Acceptable latency
        else:
            latency_color = Colors.RED     # High latency
        print_success(f"{service} port {port} is reachable on {public_ip} "
                      f"[{latency_color}{latency}ms{Colors.RESET}{Colors.GREEN}]{Colors.RESET}")
    else:
        # Connection failed — display error and troubleshooting hints
        print_error(f"{service} port {port} is NOT reachable on {public_ip}")
        print_detail(result["message"])
        print()
        print_box([
            "Possible causes:",
            f"  {BULLET} NSG rule may not have propagated yet (wait 30-60s)",
            f"  {BULLET} VM firewall (iptables/Windows Firewall) blocking port {port}",
            f"  {BULLET} {service} service not running on the VM",
            f"  {BULLET} Another NSG with a Deny rule at higher priority",
        ], color=Colors.YELLOW)


# ══════════════════════════════════════════════════════════════
# VM Processing Functions
# High-level functions that orchestrate the full workflow for
# processing one or more VMs: OS detection → NSG discovery →
# rule creation → optional connectivity testing.
# ══════════════════════════════════════════════════════════════

def process_vm(resource_id: str, source_ip: str, port_config: Optional[dict] = None,
               index: int = 0, total: int = 0, run_test: bool = False):
    """
    Process a single VM: detect OS, find/create NSGs, add appropriate rules,
    and optionally run a connectivity test.

    This is the main per-VM workflow function that:
      1. Detects the VM's OS type (Linux or Windows)
      2. Discovers all NICs and their associated NSGs
      3. Auto-creates NSGs if none exist
      4. Adds allow rules for SSH (Linux) or RDP (Windows)
      5. Optionally runs a TCP connectivity test

    Args:
        resource_id: Full Azure resource ID of the VM.
        source_ip:   The source IP address to allow in NSG rules.
        port_config: Optional dict with 'ssh_port' and 'rdp_port' overrides.
        index:       Current VM index for progress display (1-based, 0 to hide).
        total:       Total number of VMs being processed (0 to hide).
        run_test:    If True, run a connectivity test after adding rules.

    Returns:
        The os_info dict for the VM (useful for further operations),
        or None if processing failed.
    """
    vm_name_from_id = resource_id.split("/")[-1] if "/" in resource_id else resource_id
    print_vm_processing_header(vm_name_from_id, index, total)

    # Detect OS type to determine which service/port to open
    os_info = detect_vm_os(resource_id, port_config)

    os_color = Colors.CYAN if os_info["os_type"] == "Linux" else Colors.MAGENTA
    print_info(f"OS: {os_color}{Colors.BOLD}{os_info['os_type']}{Colors.RESET}  |  "
               f"Service: {Colors.BOLD}{os_info['service']}{Colors.RESET}  |  "
               f"Port: {Colors.BOLD}{os_info['port']}{Colors.RESET}")

    # Get VM's network configuration
    location = get_vm_location(resource_id)
    nic_ids = get_vm_network_interfaces(resource_id)
    if not nic_ids:
        print_warn(f"No network interfaces found for this VM.")
        return None

    print_info(f"Network interfaces: {Colors.BOLD}{len(nic_ids)}{Colors.RESET}")

    # Discover all NSGs (NIC-level and subnet-level), auto-creating if needed
    all_nsgs = []
    for nic_id in nic_ids:
        nsgs = get_nsg_from_nic(nic_id, os_info["vm_name"], location)
        for nsg in nsgs:
            if not any(n["id"] == nsg["id"] for n in all_nsgs):
                all_nsgs.append(nsg)

    if not all_nsgs:
        print_error(f"Failed to find or create NSGs for VM '{os_info['vm_name']}'.")
        return None

    print_info(f"Associated NSGs: {Colors.BOLD}{len(all_nsgs)}{Colors.RESET}")
    for nsg in all_nsgs:
        nsg_name = nsg["id"].split("/")[-1]
        print_bullet(f"{nsg_name} {Colors.DIM}(via {nsg['source']}){Colors.RESET}")

    # Add allow rules to each NSG
    print()
    for nsg in all_nsgs:
        add_access_rule_to_nsg(nsg["id"], source_ip, os_info)

    # Run connectivity test if requested
    if run_test:
        print()
        run_connectivity_test(resource_id, os_info)

    return os_info


# ══════════════════════════════════════════════════════════════
# User Input / Selection Helpers
# Functions for parsing VM selection input, validating ports,
# and building configuration objects from user input.
# ══════════════════════════════════════════════════════════════

def parse_vm_selection(selection: str, max_index: int) -> list:
    """
    Parse a user's VM selection input string into a list of 0-based indices.

    Supports multiple selection formats:
      - Single number:   "3"       → [2]
      - Comma-separated: "1,3,5"  → [0, 2, 4]
      - Range:           "2-5"    → [1, 2, 3, 4]
      - Mixed:           "1,3-5,7" → [0, 2, 3, 4, 6]
      - All:             "all"    → [0, 1, 2, ..., max_index-1]

    Args:
        selection:  User input string.
        max_index:  Total number of VMs (1-based max selection value).

    Returns:
        Sorted list of 0-based indices. Invalid inputs are warned and skipped.
    """
    selection = selection.strip().lower()
    if selection in ("all", "a"):
        return list(range(max_index))

    indices = set()
    parts = selection.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start = int(start.strip())
                end = int(end.strip())
                if start < 1 or end < 1:
                    print_warn(f"Invalid range '{part}': numbers must be >= 1.")
                    continue
                if start > end:
                    start, end = end, start
                for i in range(start, end + 1):
                    if 1 <= i <= max_index:
                        indices.add(i - 1)
                    else:
                        print_warn(f"Number {i} is out of range (1-{max_index}).")
            except ValueError:
                print_warn(f"Invalid range '{part}'.")
        else:
            try:
                num = int(part)
                if 1 <= num <= max_index:
                    indices.add(num - 1)
                else:
                    print_warn(f"Number {num} is out of range (1-{max_index}).")
            except ValueError:
                print_warn(f"Invalid input '{part}'.")

    return sorted(indices)


def validate_port(port_str: str) -> Optional[str]:
    """
    Validate that a string represents a valid TCP/UDP port number (1-65535).

    Args:
        port_str: The port number as a string.

    Returns:
        The validated port as a string, or None if invalid.
    """
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return str(port)
        else:
            print_error(f"Port {port} is out of range. Must be 1-65535.")
            return None
    except ValueError:
        print_error(f"Invalid port number: '{port_str}'.")
        return None


def build_port_config(ssh_port: Optional[str] = None, rdp_port: Optional[str] = None) -> dict:
    """
    Build a port configuration dictionary with defaults.
    Uses the provided ports if given, otherwise falls back to the
    global defaults (SSH=22, RDP=3389).

    Args:
        ssh_port: Custom SSH port, or None for default.
        rdp_port: Custom RDP port, or None for default.

    Returns:
        Dict with keys: ssh_port, rdp_port.
    """
    return {
        "ssh_port": ssh_port if ssh_port else DEFAULT_SSH_PORT,
        "rdp_port": rdp_port if rdp_port else DEFAULT_RDP_PORT,
    }


# ══════════════════════════════════════════════════════════════
# UI Helper Functions
# Reusable display and interaction components used across
# multiple execution modes (interactive, test-only, remove-rules).
# ══════════════════════════════════════════════════════════════

def display_vm_table(vms: list):
    """
    Display a formatted table of VMs with index numbers, names, and resource groups.
    Used in interactive mode for VM selection.

    Args:
        vms: List of VM dicts, each with 'name' and 'resourceGroup' keys.
    """
    w = _width()
    col_widths = [5, 30, w - 45]

    # Table border and header
    print(f"  {Colors.GRAY}{CORNER_TL}{LINE_H * (w - 4)}{CORNER_TR}{Colors.RESET}")
    header_row = f" {'#':>5}  {'VM Name':<30}  {'Resource Group':<{col_widths[2]}}"
    print(f"  {Colors.GRAY}{LINE_V}{Colors.RESET}{Colors.BOLD}{header_row}{Colors.RESET}{Colors.GRAY}{LINE_V}{Colors.RESET}")
    print(f"  {Colors.GRAY}{TEE_L}{LINE_H * (w - 4)}{TEE_R}{Colors.RESET}")

    # Table rows — one per VM
    for idx, vm in enumerate(vms, 1):
        num = f"[{idx}]"
        name = vm['name']
        rg = vm['resourceGroup']

        # Truncate long names/resource groups to fit column widths
        if len(name) > 28:
            name = name[:27] + "…"
        if len(rg) > col_widths[2] - 2:
            rg = rg[:col_widths[2] - 3] + "…"

        row = f" {num:>5}  {Colors.WHITE}{name:<30}{Colors.RESET}  {Colors.DIM}{rg:<{col_widths[2]}}{Colors.RESET}"
        print(f"  {Colors.GRAY}{LINE_V}{Colors.RESET}{row}{Colors.GRAY}{LINE_V}{Colors.RESET}")

    # Table footer
    print(f"  {Colors.GRAY}{CORNER_BL}{LINE_H * (w - 4)}{CORNER_BR}{Colors.RESET}")
    print(f"  {Colors.DIM}Total: {len(vms)} VM(s){Colors.RESET}")


def select_vms_interactive(vms: list, action_label: str = "Proceed") -> list:
    """
    Interactive VM selection with confirmation loop.
    Displays selection instructions, accepts input, shows the selection
    summary, and asks for confirmation. Loops until the user confirms.

    Args:
        vms:          List of VM dicts to select from.
        action_label: Label for the confirmation prompt (e.g., "Proceed", "Test connectivity").

    Returns:
        List of selected VM dicts.
    """
    print_section("Select VMs", KEY_ICON)
    print_box([
        "Selection options:",
        f"  {BULLET} Single:          1",
        f"  {BULLET} Multiple:        1,3,5",
        f"  {BULLET} Range:           1-3",
        f"  {BULLET} Mixed:           1,3-5,7",
        f"  {BULLET} All VMs:         all",
    ])
    print()

    while True:
        selection = styled_input("Enter your selection: ").strip()
        if not selection:
            print_warn("No selection provided. Please try again.")
            continue

        selected_indices = parse_vm_selection(selection, len(vms))
        if not selected_indices:
            print_warn("No valid VMs selected. Please try again.")
            continue

        selected_vms = [vms[i] for i in selected_indices]

        # Show selection summary
        print()
        print_subsection(f"Selected {len(selected_vms)} VM(s)")
        for vm in selected_vms:
            print_bullet(f"{Colors.WHITE}{vm['name']}{Colors.RESET} {Colors.DIM}(RG: {vm['resourceGroup']}){Colors.RESET}")

        # Ask for confirmation
        print()
        confirm = styled_input(f"{action_label} with these {len(selected_vms)} VM(s)? (y/n): ").strip().lower()
        if confirm in ("y", "yes"):
            return selected_vms
        else:
            print_info("Selection cancelled. Please select again.")
            print()


# ══════════════════════════════════════════════════════════════
# Execution Mode Functions
# Top-level functions for each execution mode:
#   - interactive_mode:    Interactive VM selection + NSG configuration
#   - run_test_only_mode:  Connectivity testing without NSG changes
#   - remove_rules_interactive: Remove all custom rules (interactive VM selection)
#   - cleanup_vm_nsgs:     Remove duplicate rules only
# ══════════════════════════════════════════════════════════════

def interactive_mode(source_ip: str, port_config: Optional[dict] = None,
                     run_test: bool = False):
    """
    Run the tool in interactive mode.

    Workflow:
      1. Display session information (IP, subscription)
      2. List all VMs in the subscription in a formatted table
      3. Let the user select which VMs to configure
      4. Ask if they want to run connectivity tests
      5. Process each selected VM (add NSG rules + optional test)

    Args:
        source_ip:   The user's public IP address for NSG rules.
        port_config: Optional dict with 'ssh_port' and 'rdp_port' overrides.
        run_test:    If True, skip the test prompt and always test.
    """
    subscription = get_current_subscription()

    # Display session summary
    print_section("Session Information", GLOBE_ICON)
    print_key_value("Public IP", f"{Colors.BOLD}{source_ip}{Colors.RESET}")
    print_key_value("Subscription", subscription['name'])

    # Show port overrides if any
    if port_config:
        overrides = []
        if port_config.get("ssh_port", DEFAULT_SSH_PORT) != DEFAULT_SSH_PORT:
            overrides.append(f"SSH={port_config['ssh_port']}")
        if port_config.get("rdp_port", DEFAULT_RDP_PORT) != DEFAULT_RDP_PORT:
            overrides.append(f"RDP={port_config['rdp_port']}")
        if overrides:
            print_key_value("Port Overrides", ", ".join(overrides))

    # Retrieve and display all VMs
    vms = get_all_vms_in_subscription()
    if not vms:
        print_warn("No VMs found in current subscription. Exiting.")
        sys.exit(0)

    print_section("Available Virtual Machines", SERVER_ICON)
    display_vm_table(vms)

    # Let user select VMs
    selected_vms = select_vms_interactive(vms, action_label="Proceed")

    # Ask about connectivity testing if not set via CLI
    if not run_test:
        print()
        test_choice = styled_input("Run TCP connectivity test after configuring each VM? (y/n): ").strip().lower()
        if test_choice in ("y", "yes"):
            run_test = True

    # Process each selected VM
    print_section("Configuring NSG Rules", LOCK_ICON)
    total = len(selected_vms)
    for idx, vm in enumerate(selected_vms, 1):
        process_vm(vm["id"], source_ip, port_config, index=idx, total=total, run_test=run_test)


def run_test_only_mode(port_config: Optional[dict] = None):
    """
    Run connectivity test only mode — no NSG changes are made.

    Workflow:
      1. List all VMs in the subscription
      2. Let the user select VMs to test
      3. For each VM, detect OS, check power state, and test TCP connectivity

    Args:
        port_config: Optional dict with port overrides (affects which port is tested).
    """
    print_section("Connectivity Test Only Mode", GLOBE_ICON)
    print_info("This mode only tests TCP connectivity. No NSG rules will be modified.")

    vms = get_all_vms_in_subscription()
    if not vms:
        print_warn("No VMs found in current subscription. Exiting.")
        sys.exit(0)

    # Display VM table and select VMs
    print_section("Available Virtual Machines", SERVER_ICON)
    display_vm_table(vms)
    selected_vms = select_vms_interactive(vms, action_label="Test connectivity")

    # Run connectivity tests
    print_section("Connectivity Tests", GLOBE_ICON)
    print_info("Testing TCP connectivity to selected VMs...")
    print_detail("Checking VM power state and testing service port reachability.")
    print()

    for idx, vm in enumerate(selected_vms, 1):
        vm_name = vm["name"]
        print_vm_processing_header(vm_name, idx, len(selected_vms))

        os_info = detect_vm_os(vm["id"], port_config)

        os_color = Colors.CYAN if os_info["os_type"] == "Linux" else Colors.MAGENTA
        print_info(f"OS: {os_color}{Colors.BOLD}{os_info['os_type']}{Colors.RESET}  |  "
                   f"Service: {Colors.BOLD}{os_info['service']}{Colors.RESET}  |  "
                   f"Port: {Colors.BOLD}{os_info['port']}{Colors.RESET}")

        run_connectivity_test(vm["id"], os_info)
        print()

    print_completion_banner("Connectivity tests complete")


def cleanup_vm_nsgs(resource_id: str):
    """
    Clean up duplicate rules in all NSGs associated with a VM.
    This only removes duplicates — it does not remove any unique rules.

    Args:
        resource_id: Full Azure resource ID of the VM.
    """
    vm_name = resource_id.split("/")[-1] if "/" in resource_id else resource_id
    print_vm_processing_header(vm_name)
    print_info("Running duplicate rule cleanup...")

    nic_ids = get_vm_network_interfaces(resource_id)
    if not nic_ids:
        print_warn("No network interfaces found for this VM.")
        return

    # Track processed NSGs to avoid checking the same NSG twice
    # (multiple NICs or subnets might share the same NSG)
    processed_nsgs = set()
    for nic_id in nic_ids:
        nic = run_az_command(["network", "nic", "show", "--ids", nic_id])

        # Check NIC-level NSG
        nic_nsg = nic.get("networkSecurityGroup")
        if nic_nsg:
            nsg_id = nic_nsg["id"]
            if nsg_id not in processed_nsgs:
                processed_nsgs.add(nsg_id)
                parts = nsg_id.split("/")
                rg_idx = parts.index("resourceGroups") + 1
                nsg_idx = parts.index("networkSecurityGroups") + 1
                remove_duplicate_rules(parts[nsg_idx], parts[rg_idx])

        # Check subnet-level NSGs
        ip_configs = nic.get("ipConfigurations", [])
        for ip_config in ip_configs:
            subnet = ip_config.get("subnet")
            if subnet:
                subnet_id = subnet["id"]
                parts = subnet_id.split("/")
                rg_idx = parts.index("resourceGroups") + 1
                vnet_idx = parts.index("virtualNetworks") + 1
                subnet_idx = parts.index("subnets") + 1

                subnet_info = run_az_command([
                    "network", "vnet", "subnet", "show",
                    "--resource-group", parts[rg_idx],
                    "--vnet-name", parts[vnet_idx],
                    "--name", parts[subnet_idx],
                ])
                subnet_nsg = subnet_info.get("networkSecurityGroup")
                if subnet_nsg:
                    nsg_id = subnet_nsg["id"]
                    if nsg_id not in processed_nsgs:
                        processed_nsgs.add(nsg_id)
                        nsg_parts = nsg_id.split("/")
                        nsg_rg_idx = nsg_parts.index("resourceGroups") + 1
                        nsg_name_idx = nsg_parts.index("networkSecurityGroups") + 1
                        remove_duplicate_rules(nsg_parts[nsg_name_idx], nsg_parts[nsg_rg_idx])


# ══════════════════════════════════════════════════════════════
# Main Entry Point
# Parses CLI arguments and dispatches to the appropriate
# execution mode. Supports:
#   - Interactive mode (default, no arguments)
#   - Single VM mode (--resource-id)
#   - All VMs mode (--all)
#   - Connectivity test only (--test-only)
#   - Remove all rules (--remove-rules)
#   - Cleanup duplicates only (--cleanup-only)
# ══════════════════════════════════════════════════════════════

def main():
    """
    Main entry point for the Azure NSG SSH/RDP Access Manager.

    Parses command-line arguments, validates inputs, and dispatches
    to the appropriate execution mode based on the provided flags.
    If no arguments are provided, defaults to interactive mode.
    """
    parser = argparse.ArgumentParser(
        description="Azure NSG SSH/RDP Access Manager - "
                    "Detects your public IP and configures NSG rules to allow SSH (Linux) or RDP (Windows) access.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (lists VMs and lets you pick)
  python azure_access_manager.py

  # Specify a VM resource ID
  python azure_access_manager.py --resource-id /subscriptions/.../virtualMachines/myVM

  # Allow access to all VMs in subscription
  python azure_access_manager.py --all

  # Override detected IP
  python azure_access_manager.py --ip 203.0.113.50 --resource-id /subscriptions/.../virtualMachines/myVM

  # Override SSH port only
  python azure_access_manager.py --ssh-port 2222 --resource-id /subscriptions/.../virtualMachines/myLinuxVM

  # Override RDP port only
  python azure_access_manager.py --rdp-port 13389 --resource-id /subscriptions/.../virtualMachines/myWinVM

  # Override both SSH and RDP ports
  python azure_access_manager.py --ssh-port 2222 --rdp-port 13389 --all

  # Run connectivity test after configuring rules
  python azure_access_manager.py --test --resource-id /subscriptions/.../virtualMachines/myVM

  # Connectivity test only (no NSG changes)
  python azure_access_manager.py --test-only

  # Connectivity test only for a specific VM
  python azure_access_manager.py --test-only --resource-id /subscriptions/.../virtualMachines/myVM

  # Connectivity test only for all VMs
  python azure_access_manager.py --test-only --all

  # Remove all custom rules (interactive VM selection)
  python azure_access_manager.py --remove-rules

  # Remove all custom rules for a specific VM
  python azure_access_manager.py --remove-rules --resource-id /subscriptions/.../virtualMachines/myVM

  # Remove all custom rules for all VMs
  python azure_access_manager.py --remove-rules --all

  # Cleanup duplicate rules only
  python azure_access_manager.py --cleanup-only --resource-id /subscriptions/.../virtualMachines/myVM
        """,
    )

    # ── Target Selection Arguments ────────────────────────────
    parser.add_argument(
        "--resource-id",
        help="Azure VM Resource ID to configure access for.",
        default=None,
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Apply to all VMs in current subscription.",
    )

    # ── Network Configuration Arguments ───────────────────────
    parser.add_argument(
        "--ip",
        help="Override auto-detected public IP address.",
        default=None,
    )
    parser.add_argument(
        "--ssh-port",
        help=f"Override default SSH port (default: {DEFAULT_SSH_PORT}). Applied to Linux VMs.",
        default=None,
    )
    parser.add_argument(
        "--rdp-port",
        help=f"Override default RDP port (default: {DEFAULT_RDP_PORT}). Applied to Windows VMs.",
        default=None,
    )

    # ── Execution Mode Arguments ──────────────────────────────
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode (default if no arguments provided).",
    )
    parser.add_argument(
        "--cleanup-only",
        action="store_true",
        help="Only remove duplicate NSG rules without adding new ones.",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run TCP connectivity test after configuring NSG rules.",
    )
    parser.add_argument(
        "--test-only",
        action="store_true",
        help="Run TCP connectivity test only without modifying NSG rules.",
    )
    parser.add_argument(
        "--remove-rules",
        action="store_true",
        help="Remove ALL custom security rules from NSGs associated with the selected VMs.",
    )

    # ── Display Arguments ─────────────────────────────────────
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output.",
    )

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color:
        Colors.disable()

    # Print the application banner
    print_banner()

    # ── Configuration Summary ─────────────────────────────────
    # Display the detected platform and port configuration
    print_section("Configuration", GEAR_ICON)
    print_key_value("Platform", PLATFORM['platform'])

    # Validate and build port configuration from CLI arguments
    ssh_port = None
    rdp_port = None

    if args.ssh_port:
        ssh_port = validate_port(args.ssh_port)
        if not ssh_port:
            sys.exit(1)

    if args.rdp_port:
        rdp_port = validate_port(args.rdp_port)
        if not rdp_port:
            sys.exit(1)

    port_config = build_port_config(ssh_port, rdp_port)

    # Display port configuration with custom port indicators
    ssh_display = port_config["ssh_port"]
    rdp_display = port_config["rdp_port"]
    ssh_note = f" {Colors.YELLOW}(custom){Colors.RESET}" if ssh_display != DEFAULT_SSH_PORT else ""
    rdp_note = f" {Colors.YELLOW}(custom){Colors.RESET}" if rdp_display != DEFAULT_RDP_PORT else ""
    print_key_value("Linux VMs", f"SSH port {ssh_display}{ssh_note}")
    print_key_value("Windows VMs", f"RDP port {rdp_display}{rdp_note}")

    # Display enabled features
    features = []
    features.append(f"{Colors.GREEN}{CHECK}{Colors.RESET} Auto-create NSGs")
    features.append(f"{Colors.GREEN}{CHECK}{Colors.RESET} Remove duplicates")
    features.append(f"{Colors.GREEN}{CHECK}{Colors.RESET} Skip existing rules")
    print_key_value("Features", " │ ".join(features))

    # ── Dispatch to Execution Mode ────────────────────────────
    # Each mode handles authentication, VM selection, and execution independently

    # Mode: Test-only (no NSG modifications)
    if args.test_only:
        print_section("Authentication", KEY_ICON)
        ensure_authenticated()

        if args.resource_id:
            # Test a specific VM by resource ID
            if not args.resource_id.startswith("/subscriptions/"):
                print_error("Invalid resource ID format.")
                sys.exit(1)
            print_section("Connectivity Test", GLOBE_ICON)
            print_info("Testing connectivity only. No NSG rules will be modified.")
            print()
            os_info = detect_vm_os(args.resource_id, port_config)
            os_color = Colors.CYAN if os_info["os_type"] == "Linux" else Colors.MAGENTA
            print_info(f"OS: {os_color}{Colors.BOLD}{os_info['os_type']}{Colors.RESET}  |  "
                       f"Service: {Colors.BOLD}{os_info['service']}{Colors.RESET}  |  "
                       f"Port: {Colors.BOLD}{os_info['port']}{Colors.RESET}")
            run_connectivity_test(args.resource_id, os_info)
        elif args.all:
            # Test all VMs in the subscription
            print_section("Connectivity Tests", GLOBE_ICON)
            print_info("Testing connectivity for all VMs. No NSG rules will be modified.")
            print()
            vms = get_all_vms_in_subscription()
            if not vms:
                print_warn("No VMs found. Exiting.")
                sys.exit(0)
            for idx, vm in enumerate(vms, 1):
                print_vm_processing_header(vm["name"], idx, len(vms))
                os_info = detect_vm_os(vm["id"], port_config)
                os_color = Colors.CYAN if os_info["os_type"] == "Linux" else Colors.MAGENTA
                print_info(f"OS: {os_color}{Colors.BOLD}{os_info['os_type']}{Colors.RESET}  |  "
                           f"Service: {Colors.BOLD}{os_info['service']}{Colors.RESET}  |  "
                           f"Port: {Colors.BOLD}{os_info['port']}{Colors.RESET}")
                run_connectivity_test(vm["id"], os_info)
                print()
        else:
            # Interactive test-only mode
            run_test_only_mode(port_config)

        print_completion_banner("Connectivity tests complete")
        return

    # Mode: Remove all custom rules
    if args.remove_rules:
        print_section("Authentication", KEY_ICON)
        ensure_authenticated()

        if args.resource_id:
            # Remove rules for a specific VM
            if not args.resource_id.startswith("/subscriptions/"):
                print_error("Invalid resource ID format.")
                sys.exit(1)
            print_section("Remove All Custom Rules", TRASH_ICON)
            print_warn("Removing all custom security rules for the specified VM.")
            print_detail("Default Azure rules will not be affected.")
            print()

            # Confirm before proceeding
            confirm = styled_input("Type 'DELETE' to confirm rule removal: ").strip()
            if confirm != "DELETE":
                print_info("Operation cancelled. No rules were modified.")
                return

            remove_all_rules_for_vm(args.resource_id)
            print_completion_banner("All custom rules removed successfully")
        elif args.all:
            # Remove rules for all VMs
            print_section("Remove All Custom Rules", TRASH_ICON)
            print_warn("Removing all custom security rules for ALL VMs in this subscription.")
            print_detail("Default Azure rules will not be affected.")
            print()

            vms = get_all_vms_in_subscription()
            if not vms:
                print_warn("No VMs found. Exiting.")
                sys.exit(0)

            # Show what will be affected
            print_info(f"This will affect {Colors.BOLD}{len(vms)}{Colors.RESET} VM(s):")
            for vm in vms:
                print_bullet(f"{Colors.WHITE}{vm['name']}{Colors.RESET} {Colors.DIM}(RG: {vm['resourceGroup']}){Colors.RESET}")
            print()

            # Confirm before proceeding
            confirm = styled_input("Type 'DELETE' to confirm rule removal for ALL VMs: ").strip()
            if confirm != "DELETE":
                print_info("Operation cancelled. No rules were modified.")
                return

            print_section("Removing Rules", TRASH_ICON)
            for idx, vm in enumerate(vms, 1):
                remove_all_rules_for_vm(vm["id"])

            print_completion_banner("All custom rules removed successfully")
        else:
            # Interactive remove-rules mode
            remove_rules_interactive()
        return

    # Mode: Cleanup duplicate rules
    if args.cleanup_only:
        print_section("Authentication", KEY_ICON)
        ensure_authenticated()

        print_section("Cleanup Mode", GEAR_ICON)
        print_info("Running in cleanup-only mode (removing duplicate rules)...")
        if args.resource_id:
            if not args.resource_id.startswith("/subscriptions/"):
                print_error("Invalid resource ID format.")
                sys.exit(1)
            cleanup_vm_nsgs(args.resource_id)
        elif args.all:
            vms = get_all_vms_in_subscription()
            if not vms:
                print_warn("No VMs found. Exiting.")
                sys.exit(0)
            total = len(vms)
            for idx, vm in enumerate(vms, 1):
                cleanup_vm_nsgs(vm["id"])
        else:
            print_error("--cleanup-only requires --resource-id or --all.")
            sys.exit(1)
        print_completion_banner("Cleanup complete")
        return

    # ── Authentication for NSG modification modes ─────────────
    print_section("Authentication", KEY_ICON)
    ensure_authenticated()

    # ── IP Detection ──────────────────────────────────────────
    print_section("Network Detection", GLOBE_ICON)
    if args.ip:
        source_ip = args.ip
        print_info(f"Using provided IP: {Colors.BOLD}{source_ip}{Colors.RESET}")
    else:
        source_ip = get_public_ip()

    # ── Main Execution Paths ──────────────────────────────────
    if args.resource_id:
        if not args.resource_id.startswith("/subscriptions/"):
            print_error("Invalid resource ID format.")
            sys.exit(1)
        print_section("Configuring NSG Rules", LOCK_ICON)
        process_vm(args.resource_id, source_ip, port_config, index=1, total=1, run_test=args.test)

    elif args.all:
        vms = get_all_vms_in_subscription()
        if not vms:
            print_warn("No VMs found. Exiting.")
            sys.exit(0)
        print_section("Configuring NSG Rules", LOCK_ICON)
        total = len(vms)
        for idx, vm in enumerate(vms, 1):
            process_vm(vm["id"], source_ip, port_config, index=idx, total=total, run_test=args.test)

    elif args.interactive or len(sys.argv) == 1:
        interactive_mode(source_ip, port_config, run_test=args.test)

    else:
        parser.print_help()
        return

    print_completion_banner("Access configuration complete")


if __name__ == "__main__":
    main()
