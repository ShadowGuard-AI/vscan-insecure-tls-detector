# vscan-insecure-tls-detector
A command-line tool that identifies potentially insecure TLS configurations (e.g., weak ciphers, outdated TLS versions) on a target website or server. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-insecure-tls-detector`

## Usage
`./vscan-insecure-tls-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--port`: No description provided
- `--timeout`: No description provided
- `--verbose`: Enable verbose output for debugging.

## License
Copyright (c) ShadowStrikeHQ

## Behaviour notes
Certificates are fetched with a non-verifying connection for inspection, so self signed, expired, not yet valid, and hostname mismatched certificates are reported as findings instead of blocking the scan. Each TLS version is probed with its minimum and maximum pinned to that version, and each weak cipher suite is offered to the server in turn. If no check can be performed (for example the port is closed), the scan reports failure and exits non-zero instead of reporting a clean result. A port written in a URL target (for example https://host:8443) takes precedence over --port.
