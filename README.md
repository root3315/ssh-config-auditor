# SSH Config Auditor

A comprehensive Bash tool for auditing SSH configuration files for security issues and misconfigurations.

## Description

SSH Config Auditor scans `sshd_config` and `ssh_config` files to identify security vulnerabilities, weak cryptographic settings, and configuration issues. It provides detailed reports with severity levels and actionable recommendations.

## Features

- **Comprehensive Security Checks**: Detects 25+ security issues including:
  - Weak authentication settings (PermitRootLogin, PasswordAuthentication)
  - Dangerous forwarding options (X11, TCP, Agent forwarding)
  - Weak cryptographic algorithms (ciphers, MACs, key exchange)
  - Protocol vulnerabilities (SSH Protocol 1)
  - Logging and session management issues

- **Multiple Output Formats**: Text (default), JSON, and CSV

- **Severity Classification**: Issues categorized as Critical, High, Medium, Low, or Info

- **No Dependencies**: Pure Bash implementation, works on any Unix-like system

## Installation

### Manual Installation

1. Clone or download the repository:
   ```bash
   git clone <repository-url>
   cd ssh-config-auditor
   ```

2. Make the main script executable:
   ```bash
   chmod +x ssh-config-auditor.sh
   ```

3. (Optional) Install system-wide:
   ```bash
   sudo cp ssh-config-auditor.sh /usr/local/bin/ssh-audit
   sudo cp -r lib /usr/local/lib/ssh-config-auditor/
   ```

### Requirements

- Bash 4.0 or later
- Standard Unix utilities (grep, sed, awk)
- No external dependencies

## Usage

### Basic Usage

```bash
# Audit a single config file
./ssh-config-auditor.sh /etc/ssh/sshd_config

# Audit multiple files
./ssh-config-auditor.sh /etc/ssh/sshd_config ~/.ssh/config

# Verbose output
./ssh-config-auditor.sh -v /etc/ssh/sshd_config
```

### Output Formats

```bash
# Text format (default)
./ssh-config-auditor.sh -f text /etc/ssh/sshd_config

# JSON format (for CI/CD integration)
./ssh-config-auditor.sh -f json /etc/ssh/sshd_config

# CSV format (for spreadsheet analysis)
./ssh-config-auditor.sh -f csv /etc/ssh/sshd_config
```

### Check Levels

```bash
# Basic checks only
./ssh-config-auditor.sh -l basic /etc/ssh/sshd_config

# Standard checks (default)
./ssh-config-auditor.sh -l standard /etc/ssh/sshd_config

# Strict checks (includes all recommendations)
./ssh-config-auditor.sh -l strict -r /etc/ssh/sshd_config
```

### Saving Reports

```bash
# Save report to file
./ssh-config-auditor.sh -o audit_report.txt /etc/ssh/sshd_config

# JSON report for automation
./ssh-config-auditor.sh -f json -o report.json /etc/ssh/sshd_config
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-v, --verbose` | Enable verbose output |
| `-q, --quiet` | Suppress non-essential output |
| `-o, --output FILE` | Write results to FILE |
| `-f, --format FORMAT` | Output format: text, json, csv |
| `-l, --level LEVEL` | Check level: basic, standard, strict |
| `-r, --recommended` | Include recommended checks |
| `--version` | Show version information |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Low severity issues found |
| 2 | Medium severity issues found |
| 3 | High severity issues found |
| 4 | Critical severity issues found |
| 5 | Error during execution |

## How It Works

### Architecture

```
ssh-config-auditor.sh    # Main entry point
├── lib/
│   ├── config_parser.sh    # Configuration file parsing
│   ├── security_checks.sh  # Security check functions
│   └── reporter.sh         # Report generation
└── tests/
    └── test_auditor.sh     # Test suite
```

### Security Checks

The auditor performs the following checks:

#### Authentication Security
- **PermitRootLogin**: Detects if root login is permitted
- **PasswordAuthentication**: Warns about password-based auth
- **PermitEmptyPasswords**: Critical check for empty passwords
- **HostbasedAuthentication**: Legacy auth method detection
- **ChallengeResponseAuthentication**: Keyboard-interactive auth

#### Cryptographic Security
- **Ciphers**: Detects weak encryption algorithms (3DES, ARCFOUR, CBC modes)
- **MACs**: Identifies weak message authentication codes (MD5, SHA1)
- **KexAlgorithms**: Finds weak key exchange methods (DH group1, SHA1)
- **Protocol**: SSH Protocol 1 detection (deprecated)

#### Access Control
- **X11Forwarding**: X11 forwarding risks
- **AllowTcpForwarding**: TCP tunneling concerns
- **AllowAgentForwarding**: SSH agent exposure
- **GatewayPorts**: Remote port binding risks
- **PermitTunnel**: Layer 2/3 tunneling

#### Session Security
- **StrictModes**: File permission checking
- **IgnoreRhosts**: Legacy rhosts authentication
- **LoginGraceTime**: Connection timeout settings
- **MaxAuthTries**: Brute force protection
- **ClientAliveInterval**: Dead connection detection

#### Logging & Monitoring
- **LogLevel**: Audit trail completeness
- **SyslogFacility**: Log destination
- **PrintLastLog**: User security awareness

### Configuration File Parsing

The parser handles:
- Comments (full-line and inline)
- Various whitespace formats
- Match blocks (sshd_config)
- Multi-value directives
- Both space and `=` separators

### Report Generation

Reports include:
- Summary of issues by severity
- Detailed findings with current vs. recommended values
- Actionable recommendations
- Timestamp and tool version

## Examples

### Example: Insecure Configuration

```bash
$ ./ssh-config-auditor.sh insecure_sshd_config

================================================================================
                    SSH CONFIG SECURITY AUDIT REPORT
================================================================================
Generated: 2024-01-15 10:30:00

--------------------------------------------------------------------------------
SUMMARY
--------------------------------------------------------------------------------
  Critical: 3
  High:     2
  Medium:   3
  Low:      2
  Info:     1
  --------------------------------
  TOTAL:    11

--------------------------------------------------------------------------------
FINDINGS
--------------------------------------------------------------------------------

=== CRITICAL SEVERITY ISSUES ===

[CRITICAL] PermitRootLogin
  File:       insecure_sshd_config
  Current:    yes
  Recommended: no
  Issue:      Root login is permitted. This is a critical security risk.

[CRITICAL] Ciphers
  File:       insecure_sshd_config
  Current:    3des-cbc,aes256-gcm@openssh.com
  Recommended: aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
  Issue:      Weak ciphers detected: 3des-cbc
```

### Example: CI/CD Integration

```bash
#!/bin/bash
# Run audit and fail on critical issues
./ssh-config-auditor.sh -f json -o report.json /etc/ssh/sshd_config

# Check exit code
case $? in
    0) echo "Audit passed" ;;
    4) echo "Critical issues found!" && exit 1 ;;
    *) echo "Issues found, review report.json" ;;
esac
```

## Testing

Run the test suite:

```bash
chmod +x tests/test_auditor.sh
./tests/test_auditor.sh
```

The test suite includes:
- Unit tests for config parsing
- Unit tests for security checks
- Unit tests for report generation
- Integration tests with sample configs

## Security Recommendations

Based on audit findings, here are common remediations:

### Critical Priority
```bash
# Disable root login
PermitRootLogin no

# Disable empty passwords
PermitEmptyPasswords no

# Use strong ciphers only
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# Use strong MACs only
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

# Use strong key exchange
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512
```

### High Priority
```bash
# Disable password authentication (use keys)
PasswordAuthentication no

# Enable strict modes
StrictModes yes

# Disable host-based auth
HostbasedAuthentication no
IgnoreRhosts yes
```

## License

This project is provided as-is for educational and security auditing purposes.

## Contributing

Contributions are welcome. Please ensure:
- All tests pass
- New checks include test coverage
- Follow existing code style
- Document new features
