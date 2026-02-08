# Azure NSG SSH/RDP Access Manager — Detailed Documentation

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Platform Support](#platform-support)
- [Authentication](#authentication)
- [Execution Modes](#execution-modes)
  - [Interactive Mode](#interactive-mode)
  - [Single VM Mode](#single-vm-mode)
  - [All VMs Mode](#all-vms-mode)
  - [Test-Only Mode](#test-only-mode)
  - [Remove Rules Mode](#remove-rules-mode)
  - [Cleanup-Only Mode](#cleanup-only-mode)
- [Command-Line Reference](#command-line-reference)
- [Features In Depth](#features-in-depth)
  - [Public IP Detection](#public-ip-detection)
  - [OS Detection](#os-detection)
  - [NSG Discovery and Auto-Creation](#nsg-discovery-and-auto-creation)
  - [Rule Deduplication](#rule-deduplication)
  - [Existing Rule Detection](#existing-rule-detection)
  - [Custom Port Override](#custom-port-override)
  - [Connectivity Testing](#connectivity-testing)
  - [VM Power State Detection](#vm-power-state-detection)
- [Examples](#examples)
  - [Basic Usage](#basic-usage)
  - [Custom Ports](#custom-ports)
  - [Connectivity Testing](#connectivity-testing-examples)
  - [Rule Management](#rule-management)
  - [Bulk Operations](#bulk-operations)
  - [CI/CD and Automation](#cicd-and-automation)
- [NSG Rule Naming Convention](#nsg-rule-naming-convention)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Error Reference](#error-reference)

---

## Overview

`azure_access_manager.py` is a Python command-line tool that simplifies remote access configuration for Azure Virtual Machines. It automates the process of:

1. Detecting your current public IP address
2. Identifying whether a VM runs Linux (SSH) or Windows (RDP)
3. Finding or creating the appropriate Network Security Groups (NSGs)
4. Adding inbound allow rules scoped to your IP address
5. Verifying connectivity with TCP handshake tests
6. Offering to start stopped/deallocated VMs and re-testing automatically

The tool eliminates the need to manually navigate the Azure Portal or write complex `az` CLI commands to configure NSG rules for remote access.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        azure_access_manager.py                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ IP Detection │  │ OS Detection │  │ NSG Management   │  │
│  │              │  │              │  │                  │  │
│  │ • ipify      │  │ • osProfile  │  │ • Discovery      │  │
│  │ • ifconfig   │  │ • osDisk     │  │ • Auto-creation  │  │
│  │ • amazonaws  │  │ • imageRef   │  │ • Rule creation  │  │
│  └──────┬───────┘  └──────┬───────┘  │ • Deduplication  │  │
│         │                 │          │ • Skip existing  │  │
│         │                 │          └────────┬─────────┘  │
│         │                 │                   │            │
│         └─────────┬───────┘                   │            │
│                   │                           │            │
│         ┌─────────▼───────────────────────────▼──────┐     │
│         │           Azure CLI (az)                    │     │
│         │  • az vm show / list                       │     │
│         │  • az network nsg create / rule create     │     │
│         │  • az network nic show / update            │     │
│         │  • az network vnet subnet show / update    │     │
│         └─────────────────────────────────────────────┘     │
│                                                             │
│  ┌──────────────────┐  ┌─────────────────────────────┐     │
│  │ Connectivity     │  │ Platform Detection          │     │
│  │                  │  │                             │     │
│  │ • Power state    │  │ • Windows (az.cmd, shell)   │     │
│  │ • Public IP      │  │ • WSL (native az / az.cmd)  │     │
│  │ • TCP handshake  │  │ • Linux/macOS (az)          │     │
│  └──────────────────┘  └─────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Component Flow

```
User runs azure_access_manager.py
       │
       ▼
┌─ Platform Detection ──────────────────────────┐
│  Detect Windows / WSL / Linux / macOS         │
│  Configure az CLI binary and shell settings   │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌─ Authentication ──────────────────────────────┐
│  Check token validity                         │
│  Refresh if expiring within 5 minutes         │
│  Interactive login if token is invalid        │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌─ IP Detection ────────────────────────────────┐
│  Query ipify → ifconfig.me → amazonaws       │
│  Or use --ip override                         │
└───────────────────────┬───────────────────────┘
                        │
                        ▼
┌─ VM Processing (per VM) ─────────────────────┐
│                                               │
│  1. Detect OS type (Linux/Windows)            │
│  2. Get NICs → find/create NSGs               │
│  3. Remove duplicate rules                    │
│  4. Check for existing allow rules            │
│  5. Add new rule if needed                    │
│  6. Run connectivity test (optional)          │
│                                               │
└───────────────────────────────────────────────┘
```

---

## Prerequisites

### Required

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.7+ | Standard library only, no pip packages needed |
| **Azure CLI** | 2.x | Must be installed and in PATH |
| **Azure Account** | — | Must be logged in via `az login` |

### Permissions

The user must have the following Azure RBAC permissions:

| Permission | Resource | Purpose |
|------------|----------|---------|
| `Microsoft.Compute/virtualMachines/read` | VMs | List and inspect VMs |
| `Microsoft.Network/networkInterfaces/read` | NICs | Read NIC configuration |
| `Microsoft.Network/networkInterfaces/write` | NICs | Attach NSGs to NICs |
| `Microsoft.Network/networkSecurityGroups/read` | NSGs | Read existing rules |
| `Microsoft.Network/networkSecurityGroups/write` | NSGs | Create NSGs and rules |
| `Microsoft.Network/virtualNetworks/subnets/read` | Subnets | Read subnet NSG associations |
| `Microsoft.Network/virtualNetworks/subnets/write` | Subnets | Attach NSGs to subnets |
| `Microsoft.Network/publicIPAddresses/read` | Public IPs | Read VM public IPs for connectivity testing |

The built-in **Network Contributor** role covers all of these permissions.

---

## Installation

No installation is required. The script uses only Python standard library modules.

```bash
# Download the script
curl -o azure_access_manager.py https://raw.githubusercontent.com/<your-repo>/azure_access_manager.py

# Or clone the repository
git clone https://github.com/<your-repo>.git
cd <your-repo>

# Verify Python version
python --version  # Must be 3.7+

# Verify Azure CLI
az --version

# Login to Azure (if not already logged in)
az login
```

### WSL Setup

If running in Windows Subsystem for Linux (WSL):

```bash
# Option 1: Install Azure CLI natively in WSL (recommended)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az login

# Option 2: Use Windows Azure CLI from WSL
# Ensure az.cmd is accessible from WSL PATH
# The tool auto-detects this and uses az.cmd if native az is not found
```

---

## Platform Support

The tool automatically detects the runtime environment:

| Platform | Azure CLI Binary | Shell Mode | Notes |
|----------|-----------------|------------|-------|
| **Windows** | `az` | `shell=True` | Uses cmd.exe; ANSI colors enabled via Win32 API |
| **WSL (native az)** | `az` | `shell=False` | Preferred WSL mode; native Linux az CLI |
| **WSL (Windows az)** | `az.cmd` | `shell=False` | Fallback when native az is not installed |
| **Linux / macOS** | `az` | `shell=False` | Standard Unix execution |

The detected platform is displayed in the Configuration section at startup:

```
  ── ⚙ Configuration ──────────────────────────────────────────
    Platform: WSL (native az)
    Linux VMs: SSH port 22
    Windows VMs: RDP port 3389
```

---

## Authentication

### Automatic Token Management

The tool manages Azure CLI authentication tokens automatically:

1. **Token check**: Validates the current access token on startup
2. **Proactive refresh**: Refreshes the token if it expires within 5 minutes
3. **Silent refresh**: Attempts `az account get-access-token` first
4. **Interactive fallback**: If silent refresh fails, triggers `az login`
5. **Mid-operation recovery**: If a command fails due to token expiry, automatically refreshes and retries

### Manual Authentication

```bash
# Standard login (opens browser)
az login

# Device code login (for headless environments)
az login --use-device-code

# Service principal login (for automation)
az login --service-principal -u <app-id> -p <password> --tenant <tenant-id>

# Set the target subscription
az account set --subscription "My Subscription"
```

---

## Execution Modes

### Interactive Mode

**Trigger**: Run with no arguments, or with `--interactive` / `-i`

```bash
python azure_access_manager.py
python azure_access_manager.py -i
python azure_access_manager.py --interactive
```

**Workflow**:
1. Displays session information (public IP, subscription)
2. Lists all VMs in a formatted table with index numbers
3. Prompts for VM selection (supports ranges, comma-separated, "all")
4. Asks whether to run connectivity tests
5. Processes each selected VM

**Example session**:
```
  ╔════════════════════════════════════════════════════════════╗
  ║  🛡 Azure NSG SSH/RDP Access Manager                      ║
  ║  Secure remote access configuration tool                   ║
  ╚════════════════════════════════════════════════════════════╝

  ── 🌐 Session Information ───────────────────────────────────
    Public IP: 203.0.113.50
    Subscription: My Azure Subscription

  ── 🖥 Available Virtual Machines ────────────────────────────
  ┌──────────────────────────────────────────────────────────┐
  │   #   VM Name                         Resource Group     │
  ├──────────────────────────────────────────────────────────┤
  │  [1]  web-server-01                   rg-production      │
  │  [2]  db-server-01                    rg-production      │
  │  [3]  dev-machine                     rg-development     │
  │  [4]  win-desktop-01                  rg-development     │
  └──────────────────────────────────────────────────────────┘
    Total: 4 VM(s)

  ── 🔑 Select VMs ───────────────────────────────────────────
  ┌──────────────────────────────────────────────────────────┐
  │ Selection options:                                       │
  │   • Single:          1                                   │
  │   • Multiple:        1,3,5                               │
  │   • Range:           1-3                                 │
  │   • Mixed:           1,3-5,7                             │
  │   • All VMs:         all                                 │
  └──────────────────────────────────────────────────────────┘

  → Enter your selection: 1,3
```

**Selection formats**:

| Input | Result |
|-------|--------|
| `1` | Select VM #1 only |
| `1,3,5` | Select VMs #1, #3, and #5 |
| `2-5` | Select VMs #2 through #5 |
| `1,3-5,7` | Select VMs #1, #3, #4, #5, and #7 |
| `all` or `a` | Select all VMs |

---

### Single VM Mode

**Trigger**: Use `--resource-id` with a full Azure VM resource ID

```bash
python azure_access_manager.py --resource-id /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/myVM
```

**Behavior**: Processes only the specified VM. Skips the VM listing and selection steps.

**With connectivity test**:
```bash
python azure_access_manager.py --resource-id /subscriptions/.../virtualMachines/myVM --test
```

---

### All VMs Mode

**Trigger**: Use `--all`

```bash
python azure_access_manager.py --all
python azure_access_manager.py --all --test
```

**Behavior**: Retrieves all VMs in the current subscription and processes each one sequentially. Each VM shows a progress counter (e.g., `[2/5]`).

---

### Test-Only Mode

**Trigger**: Use `--test-only`

```bash
# Interactive test selection
python azure_access_manager.py --test-only

# Test a specific VM
python azure_access_manager.py --test-only --resource-id /subscriptions/.../virtualMachines/myVM

# Test all VMs
python azure_access_manager.py --test-only --all
```

**Behavior**: Only tests TCP connectivity — **no NSG rules are created, modified, or deleted**. For each VM:
1. Detects the OS type and target port
2. Checks the VM's power state
3. Resolves the public IP from the primary NIC
4. Performs a TCP handshake on the service port
5. Reports success/failure with latency

**Example output**:
```
  ── Connectivity Test: web-server-01 ──────────────────────
  ✓  VM status: VM running
  ℹ  Target: 20.84.123.45:22 (SSH)
  ℹ  Testing TCP handshake...
  ✓  SSH port 22 is reachable on 20.84.123.45 [23.4ms]
```

---

### Remove Rules Mode

**Trigger**: Use `--remove-rules`

```bash
# Interactive selection
python azure_access_manager.py --remove-rules

# Remove rules for a specific VM
python azure_access_manager.py --remove-rules --resource-id /subscriptions/.../virtualMachines/myVM

# Remove rules for all VMs
python azure_access_manager.py --remove-rules --all
```

**Behavior**: Removes **ALL custom security rules** from NSGs associated with the selected VMs. Default Azure rules (priority ≥ 65000) are never removed.

**Safety features**:
- Displays all rules that will be deleted before proceeding
- Requires typing `DELETE` to confirm (not just `y`)
- Shows rule details including name, priority, direction, access, source, and port

**Example confirmation prompt**:
```
  ┌──────────────────────────────────────────────────────────┐
  │ ⚠ WARNING: This action will delete ALL custom NSG rules  │
  │   for the selected 2 VM(s).                              │
  │                                                          │
  │   This includes SSH/RDP allow rules, custom deny rules,  │
  │   and any other manually or auto-created security rules.  │
  │                                                          │
  │   Default Azure rules will NOT be affected.              │
  └──────────────────────────────────────────────────────────┘

  → Type 'DELETE' to confirm rule removal:
```

---

### Cleanup-Only Mode

**Trigger**: Use `--cleanup-only` with `--resource-id` or `--all`

```bash
# Cleanup a specific VM's NSGs
python azure_access_manager.py --cleanup-only --resource-id /subscriptions/.../virtualMachines/myVM

# Cleanup all VMs' NSGs
python azure_access_manager.py --cleanup-only --all
```

**Behavior**: Only removes **duplicate** NSG rules. Does not add any new rules. Useful for maintenance when rules have accumulated over time.

---

## Command-Line Reference

```
usage: azure_access_manager.py [-h] [--resource-id RESOURCE_ID] [--all] [--ip IP]
                [--ssh-port SSH_PORT] [--rdp-port RDP_PORT]
                [--interactive] [--cleanup-only] [--test] [--test-only]
                [--remove-rules] [--no-color]
```

### Target Selection

| Argument | Description |
|----------|-------------|
| `--resource-id ID` | Full Azure resource ID of a specific VM |
| `--all` | Target all VMs in the current subscription |

### Network Configuration

| Argument | Default | Description |
|----------|---------|-------------|
| `--ip ADDRESS` | Auto-detected | Override the source IP used in NSG rules |
| `--ssh-port PORT` | `22` | Custom SSH port for Linux VMs |
| `--rdp-port PORT` | `3389` | Custom RDP port for Windows VMs |

### Execution Modes

| Argument | Description |
|----------|-------------|
| `--interactive`, `-i` | Interactive mode (default when no args) |
| `--test` | Run connectivity test after configuring rules |
| `--test-only` | Test connectivity only, no NSG modifications |
| `--remove-rules` | Remove all custom security rules |
| `--cleanup-only` | Remove duplicate rules only |

### Display

| Argument | Description |
|----------|-------------|
| `--no-color` | Disable ANSI color codes in output |

---

## Features In Depth

### Public IP Detection

The tool detects your public-facing IP address by querying external HTTP services. Three services are tried in order for redundancy:

| Priority | Service | URL |
|----------|---------|-----|
| 1 | ipify | `https://api.ipify.org` |
| 2 | ifconfig.me | `https://ifconfig.me/ip` |
| 3 | AWS Check IP | `https://checkip.amazonaws.com` |

Each service has a 10-second timeout. The first successful response is used.

**Override**: Use `--ip` to skip auto-detection:
```bash
python azure_access_manager.py --ip 203.0.113.50 --all
```

---

### OS Detection

The tool uses a multi-strategy approach to determine if a VM runs Linux or Windows:

| Priority | Strategy | Source Field |
|----------|----------|-------------|
| 1 | OS Profile | `osProfile.windowsConfiguration` / `osProfile.linuxConfiguration` |
| 2 | OS Disk Type | `storageProfile.osDisk.osType` |
| 3 | Image Reference | `storageProfile.imageReference.publisher`, `.offer`, `.sku` |
| 4 | Fallback | Defaults to **Linux (SSH)** if all strategies fail |

**Detection result mapping**:

| Detected OS | Service | Default Port |
|-------------|---------|-------------|
| Linux | SSH | 22 |
| Windows | RDP | 3389 |

---

### NSG Discovery and Auto-Creation

For each VM, the tool checks two levels of NSG association:

```
VM
 └── NIC (Network Interface)
      ├── NIC-level NSG ← checked first
      └── IP Configuration
           └── Subnet
                └── Subnet-level NSG ← checked second
```

**Auto-creation behavior**:

| Scenario | Action |
|----------|--------|
| NIC has NSG, Subnet has NSG | Use both existing NSGs |
| NIC has NSG, Subnet has no NSG | Use NIC NSG + create new subnet NSG |
| NIC has no NSG, Subnet has NSG | Create new NIC NSG + use subnet NSG |
| Neither has NSG | Create both NIC and subnet NSGs |

**Auto-created NSG naming**:
- NIC-level: `nsg-{vm-name}-nic-{unix-timestamp}`
- Subnet-level: `nsg-{subnet-name}-subnet-{unix-timestamp}`

---

### Rule Deduplication

Before adding any new rules, the tool scans for and removes duplicate rules in each NSG. Two rules are considered duplicates if they share the same:

- Direction (Inbound/Outbound)
- Access (Allow/Deny)
- Protocol (TCP/UDP/*)
- Source address prefix
- Source port range
- Destination address prefix
- Destination port range

When duplicates are found, the rule with the **lowest priority number** (highest precedence) is kept, and all others are deleted.

---

### Existing Rule Detection

Before creating a new allow rule, the tool checks if the required access is already granted by an existing rule. The check evaluates rules in priority order and considers:

- **Source matching**: Exact IP, CIDR notation (`/32`, `/24`, etc.), wildcards (`*`, `Internet`, `Any`)
- **Port matching**: Exact port, port ranges (`1000-2000`), wildcards (`*`)
- **Deny detection**: If a higher-priority deny rule matches before any allow rule, the tool does NOT add the rule (it would be ineffective)

**Example skip message**:
```
  → SSH access already allowed by existing rule:
       Rule: 'Allow-SSH-203-0-113-50-1706300000' (priority 100)
       Source: 203.0.113.50/32 → Port: 22
```

---

### Custom Port Override

Override the default SSH and/or RDP ports independently:

```bash
# SSH on custom port
python azure_access_manager.py --ssh-port 2222 --resource-id /subscriptions/.../virtualMachines/myLinuxVM

# RDP on custom port
python azure_access_manager.py --rdp-port 13389 --resource-id /subscriptions/.../virtualMachines/myWinVM

# Both overridden
python azure_access_manager.py --ssh-port 2222 --rdp-port 13389 --all
```

- Port values must be between 1 and 65535
- The override only affects the corresponding OS type (SSH port only applies to Linux VMs, RDP port only to Windows VMs)
- Custom ports are displayed in the Configuration section at startup

---

### Connectivity Testing

The TCP connectivity test performs a socket-level three-way handshake:

```
Client (your machine)          Target VM
       │                            │
       ├──── SYN ──────────────────►│
       │                            │
       │◄─── SYN+ACK ──────────────┤
       │                            │
       ├──── ACK ──────────────────►│
       │                            │
       │    Connection established   │
```

**Test sequence per VM**:
1. Check VM power state via Azure API
2. If VM is not running:
   - Display the `az vm start` command for easy copy-paste
   - Prompt the user: "Do you want to start the VM now? (y/N)"
   - If confirmed, start the VM via Azure CLI and re-run the test
3. Resolve public IP from primary NIC
4. Attempt TCP connection with 5-second timeout
5. Report result with latency measurement

**Latency color coding**:

| Latency | Color | Quality |
|---------|-------|---------|
| < 50ms | Green | Good |
| 50-150ms | Yellow | Acceptable |
| > 150ms | Red | High |

**Error handling**: Common connection errors are mapped to human-readable messages:

| Error | Message |
|-------|---------|
| Port closed | "Connection refused" |
| Timeout | "Connection timed out" |
| No route | "No route to host" |
| DNS failure | "DNS resolution failed" |

---

### VM Power State Detection

Before testing connectivity, the tool checks the VM's power state:

| Power State | Behavior |
|-------------|----------|
| **VM running** | Proceeds with connectivity test |
| **VM stopped** | Shows `az vm start` command (copyable) and prompts to start the VM interactively |
| **VM deallocated** | Shows `az vm start` command (copyable) and prompts to start the VM interactively |
| **VM starting** | Skips test; advises to wait |

**Interactive VM Start**: When a VM is stopped or deallocated, the tool displays the `az vm start` command as a plain line outside the info box so it can be easily copied. It then asks:

```
  → Do you want to start the VM now? (y/N):
```

If confirmed (`y` or `yes`), the tool:
1. Runs `az vm start --ids <resource-id>` to start the VM
2. Waits 10 seconds for the VM to initialize
3. Automatically re-runs the connectivity test against the now-running VM

---

## Examples

### Basic Usage

**Interactive mode — select VMs from a list**:
```bash
python azure_access_manager.py
```

**Configure access for a single VM**:
```bash
python azure_access_manager.py --resource-id /subscriptions/8e44821f-d1a4-4d63-8bb7-7eca49df6ded/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/web-server-01
```

**Configure access for all VMs**:
```bash
python azure_access_manager.py --all
```

### Custom Ports

**Linux VM with SSH on port 2222**:
```bash
python azure_access_manager.py --ssh-port 2222 --resource-id /subscriptions/.../virtualMachines/myLinuxVM
```

**Windows VM with RDP on port 13389**:
```bash
python azure_access_manager.py --rdp-port 13389 --resource-id /subscriptions/.../virtualMachines/myWinVM
```

**Mixed environment with both custom ports**:
```bash
python azure_access_manager.py --ssh-port 2222 --rdp-port 13389 --all
```

### Connectivity Testing Examples

**Test after configuring rules**:
```bash
python azure_access_manager.py --test --resource-id /subscriptions/.../virtualMachines/myVM
```

**Test all VMs without making changes**:
```bash
python azure_access_manager.py --test-only --all
```

**Interactive test selection**:
```bash
python azure_access_manager.py --test-only
```

**Test a specific VM without changes**:
```bash
python azure_access_manager.py --test-only --resource-id /subscriptions/.../virtualMachines/myVM
```

### Rule Management

**Remove all custom rules (interactive selection)**:
```bash
python azure_access_manager.py --remove-rules
```

**Remove all custom rules for a specific VM**:
```bash
python azure_access_manager.py --remove-rules --resource-id /subscriptions/.../virtualMachines/myVM
```

**Remove all custom rules for all VMs**:
```bash
python azure_access_manager.py --remove-rules --all
```

**Clean up duplicate rules only**:
```bash
python azure_access_manager.py --cleanup-only --resource-id /subscriptions/.../virtualMachines/myVM
python azure_access_manager.py --cleanup-only --all
```

### Bulk Operations

**Configure and test all VMs**:
```bash
python azure_access_manager.py --all --test
```

**Use a specific IP for all VMs**:
```bash
python azure_access_manager.py --all --ip 203.0.113.50
```

**Full workflow: configure, test, custom ports**:
```bash
python azure_access_manager.py --all --test --ssh-port 2222 --rdp-port 13389
```

### CI/CD and Automation

**Non-interactive with specific IP (e.g., from a CI runner)**:
```bash
python azure_access_manager.py --all --ip $(curl -s https://api.ipify.org) --no-color
```

**Pipe output to a file**:
```bash
python azure_access_manager.py --all --no-color 2>&1 | tee azure_access_manager-output.log
```

**Set subscription before running**:
```bash
az account set --subscription "Production"
python azure_access_manager.py --all --test
```

---

## NSG Rule Naming Convention

Rules created by the tool follow this naming pattern:

```
Allow-{Service}-{IP-sanitized}-{UnixTimestamp}
```

| Component | Description | Example |
|-----------|-------------|---------|
| Service | SSH or RDP | `SSH` |
| IP-sanitized | Source IP with dots replaced by hyphens | `203-0-113-50` |
| UnixTimestamp | Unix timestamp for uniqueness | `1706300000` |

**Full example**: `Allow-SSH-203-0-113-50-1706300000`

**Rule properties**:

| Property | Value |
|----------|-------|
| Direction | Inbound |
| Access | Allow |
| Protocol | TCP |
| Source Address | `{your-ip}/32` |
| Source Port | `*` |
| Destination Address | `*` |
| Destination Port | `22` (SSH) or `3389` (RDP) |
| Priority | Auto-assigned (lowest available, starting from 100) |
| Description | `Allow {Service} from {IP} to {OS} VM '{name}' (port {port}) - auto-added` |

---

## Security Considerations

### IP Scoping

- Rules are scoped to your specific IP address (`/32` CIDR), not the entire internet
- If your IP changes (e.g., reconnecting to a different network), run the tool again to add a rule for your new IP
- Old rules for previous IPs remain until manually removed (use `--remove-rules`)

### Rule Accumulation

Over time, multiple runs with different IPs will accumulate rules. Periodically clean up:

```bash
# Remove all rules and re-add for current IP
python azure_access_manager.py --remove-rules --all
python azure_access_manager.py --all
```

### NSG Precedence

Azure evaluates NSG rules in priority order (lowest number = highest precedence):

- **Custom rules**: Priority 100-4096 (managed by this tool)
- **Default rules**: Priority 65000+ (managed by Azure, cannot be deleted)

If a deny rule exists at a lower priority number than your allow rule, the deny takes effect. The tool detects this and warns you.

### Best Practices

1. **Use `--remove-rules` before leaving** — Clean up access rules when you no longer need remote access
2. **Use custom ports** — Running SSH/RDP on non-standard ports reduces brute-force exposure
3. **Monitor NSG flow logs** — Enable NSG flow logs in Azure to audit access
4. **Use Azure Bastion for production** — For production VMs, consider Azure Bastion instead of direct NSG rules

---

## Troubleshooting

### Common Issues

#### "Azure CLI not found"

```
✗ Azure CLI ('az') not found. Please install it first.
```

**Solution**: Install Azure CLI:
- **Windows**: Download from https://aka.ms/installazurecliwindows
- **Linux/WSL**: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`
- **macOS**: `brew install azure-cli`

#### "Access token expired"

```
⚠ Access token expired or not found. Refreshing...
```

**Automatic**: The tool handles this automatically by refreshing the token or prompting for login.

**Manual**: If auto-refresh fails:
```bash
az login
```

#### "No public IP found"

```
⚠ No public IP found on primary NIC for VM 'myVM'. Skipping connectivity test.
```

**Possible causes**:
- VM has no public IP assigned
- VM is behind a load balancer or NAT gateway
- Public IP uses dynamic allocation and VM is deallocated

**Solution**: Assign a public IP or start the VM:
```bash
az vm start --name myVM --resource-group myRG
```

#### "Connection refused" during test

```
✗ SSH port 22 is NOT reachable on 20.84.123.45
  Connection refused (23.4ms)
```

**Possible causes**:
- SSH/RDP service not running on the VM
- VM-level firewall (iptables, Windows Firewall) blocking the port
- NSG rule not propagated yet (wait 30-60 seconds)

#### "Connection timed out" during test

```
✗ SSH port 22 is NOT reachable on 20.84.123.45
  Connection timed out after 5s
```

**Possible causes**:
- NSG rule not yet effective
- Another NSG with a higher-priority deny rule
- Azure firewall or route table blocking traffic

---

## Error Reference

| Error | Cause | Resolution |
|-------|-------|------------|
| `NameError: name 'source_ip' is not defined` | Using older version of the script | Update to latest version |
| `Invalid resource ID format` | Resource ID doesn't start with `/subscriptions/` | Use the full resource ID from Azure Portal |
| `No VMs found in current subscription` | Wrong subscription selected | Run `az account set --subscription "Name"` |
| `No available priority found` | All priorities 100-4096 are used (very unlikely) | Remove unused rules with `--remove-rules` |
| `Failed to detect public IP` | All IP detection services failed | Check internet connectivity; use `--ip` override |
| `Port X is out of range` | Port number not between 1-65535 | Use a valid port number |
| `Azure CLI command failed` | Generic Azure CLI error | Check the error message; ensure correct permissions |

---

## Output Color Reference

| Color | Meaning |
|-------|---------|
| 🟢 Green (`✓`) | Success / Completed operation |
| 🔵 Blue (`ℹ`) | Informational message |
| 🟡 Yellow (`⚠`) | Warning / Attention needed |
| 🔴 Red (`✗`) | Error / Failure |
| 🟣 Magenta (`→`) | Skipped operation (already done) |
| ⚪ Gray / Dim | Supporting details and context |

To disable colors (e.g., for log files):
```bash
python azure_access_manager.py --no-color --all
```

Colors are automatically disabled when stdout is piped:
```bash
python azure_access_manager.py --all | tee output.log  # Colors disabled automatically
```
