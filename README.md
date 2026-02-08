# Azure NSG SSH/RDP Access Manager (azure_access_manager.py)

A command-line tool that automatically detects your public IP address and configures Azure Network Security Group (NSG) rules to allow SSH (Linux) or RDP (Windows) access to your Azure VMs.

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Azure CLI](https://img.shields.io/badge/Azure%20CLI-Required-orange.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20WSL%20%7C%20Linux%20%7C%20macOS-green.svg)

## Features

- 🌐 **Auto-detects** your public IP address
- 🔍 **Auto-detects** VM OS type (Linux → SSH, Windows → RDP)
- 🛡️ **Auto-creates** NSGs if none are associated with a VM
- 🧹 **Removes duplicate** NSG rules automatically
- ⏭️ **Skips redundant** rules if access is already allowed
- 🔌 **Tests connectivity** with TCP handshake and latency measurement
- � **Start stopped VMs** — prompts to start deallocated/stopped VMs during connectivity tests
- �🖥️ **Cross-platform** — Windows, WSL, Linux, macOS
- 🎨 **Interactive & CLI** modes with colored terminal output

## Prerequisites

- **Python 3.7+**
- **Azure CLI** installed and logged in (`az login`)

## Quick Start

```bash
# Interactive mode — lists VMs and lets you pick
python azure_access_manager.py

# Allow access to a specific VM
python azure_access_manager.py --resource-id /subscriptions/.../virtualMachines/myVM

# Allow access to all VMs
python azure_access_manager.py --all

# Test connectivity only (no changes)
python azure_access_manager.py --test-only

# Remove all custom NSG rules
python azure_access_manager.py --remove-rules
```

## Common Options

| Flag | Description |
|------|-------------|
| `--resource-id ID` | Target a specific VM by resource ID |
| `--all` | Apply to all VMs in the subscription |
| `--ip ADDRESS` | Override auto-detected public IP |
| `--ssh-port PORT` | Custom SSH port (default: 22) |
| `--rdp-port PORT` | Custom RDP port (default: 3389) |
| `--test` | Run connectivity test after configuring rules |
| `--test-only` | Test connectivity only, no NSG changes |
| `--remove-rules` | Remove all custom security rules |
| `--cleanup-only` | Remove duplicate rules only |
| `--no-color` | Disable colored output |

## How It Works

1. Detects your public IP via external services (ipify, ifconfig.me, etc.)
2. Identifies the VM's OS type to determine SSH (port 22) or RDP (port 3389)
3. Finds all NSGs on the VM's NICs and subnets (creates them if missing)
4. Adds an inbound allow rule for your IP on the appropriate port
5. Optionally tests TCP connectivity to verify access
6. If a VM is stopped/deallocated, offers to start it and re-test automatically

## License

MIT
