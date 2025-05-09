# RDS Brute Force Blocker

A fast and lightweight PowerShell script to detect and block brute force attacks on Remote Desktop Services (RDS). Protects session hosts (RD-SH) as well as gateways (RD Gateway).

## Overview

This PowerShell script monitors Windows Event Logs for signs of repeated failed login attempts—commonly indicative of brute force attacks—targeting Remote Desktop Services. When suspicious activity is detected, the offending IP address is automatically blocked using the built-in Windows Firewall.

## Features

- **Very Fast and efficient**: Designed (.NET inline code) for speed with minimal resource usage
- **Lightweight**: No installation or external dependencies required
- **Automatic blocking**: Creates Windows Firewall rules to block attackers
- **Event Log scanning**: Detects repeated failed RDS login attempts *very* fast
- **Easy integration**: Ideal for standalone servers, existing infrastructure or Broker/Gateway setups

## How It Works

1. The script scans Windows Event Logs for multiple failed RDS login attempts
2. If an IP address exceeds a (configurable) threshold of failures, it is flagged as a potential attacker
3. The script then adds a Windows Firewall rule to block all further traffic from that IP address

## Requirements

- Windows Server (with Remote Desktop Services enabled)
- Administrator privileges (to modify firewall settings)
- PowerShell 5.1 or higher
- Windows (Defender) Firewall enabled (in active profile)

## Usage

Run the script manually or schedule it via Task Scheduler to run at regular intervals (e.g. 5 minutes).

```powershell
.\RDS-BruteForce-Blocker.ps1
