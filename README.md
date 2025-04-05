# vscan-error-code-analyzer
Scans HTTP responses for common error codes (e.g., 403 Forbidden, 500 Internal Server Error) and attempts to correlate them with potential security misconfigurations or vulnerabilities. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowStrikeHQ/vscan-error-code-analyzer`

## Usage
`./vscan-error-code-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: The User-Agent string to use.
- `-t`: The request timeout in seconds.
- `--ignore-ssl`: Ignore SSL certificate verification errors.
- `-v`: Enable verbose logging.

## License
Copyright (c) ShadowStrikeHQ
