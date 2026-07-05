# Kali Tools MCP Server (Docker)

This project builds a hardened Docker image containing:

- A Node.js MCP server (Streamable HTTP transport)
- A selected security toolset (`nmap`, `sqlmap`, `dig`, `whois`, `openssl`, `curl`, `netcat`, `dnsutils`)

## Installation & Setup

### Prerequisites

- Docker (for containerized deployment)
- Node.js 18+ (for local development)
- npm

### Install dependencies

```bash
npm install
```

## Build the Docker image

```bash
docker build -t kali-tools-mcp:latest .
```

## Run the server

### Option 1: Local development

```bash
npm start
```

By default, the server listens on `http://0.0.0.0:3000`. Override with environment variables:

```bash
HOST=127.0.0.1 PORT=8080 npm start
```

### Option 2: Docker (detached)

```bash
docker run -d --name kali-tools-mcp --rm -p 3000:3000 kali-tools-mcp:latest
```

### Option 3: Docker (hardened runtime)

```bash
docker run -d --name kali-tools-mcp --rm \
  -p 3000:3000 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 256 \
  --memory 512m \
  --cpus 1.0 \
  kali-tools-mcp:latest
```

### Health check

```bash
curl http://localhost:3000/health
```

### Stop the container

```bash
docker stop kali-tools-mcp
```

## MCP Configuration

### Endpoint

```text
http://localhost:3000/mcp
```

### Example MCP client config

Use this in an MCP-compatible client that supports Streamable HTTP servers:

```json
{
  "mcpServers": {
    "kali-tools": {
      "type": "streamable-http",
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

## Exposed Tools

### Reconnaissance & Discovery

- **`nmap_scan`**: Run `nmap` with a controlled set of options (`-sV`, `-sT`, `-Pn`, `-A`, `-F`)
- **`dig_lookup`**: Resolve DNS records via `dig` (A, AAAA, CNAME, MX, TXT, NS)
- **`whois_lookup`**: Fetch WHOIS information for a domain

### Web & TLS Analysis

- **`http_headers_check`**: Fetch HTTP response headers from a URL (supports redirect following and insecure TLS)
- **`tls_certificate_check`**: Inspect TLS certificate and handshake details for a host
- **`nmap_ssl_cipher_scan`**: Enumerate supported TLS ciphers on a target

### Vulnerability Scanning

- **`sqlmap_url_scan`**: Run a bounded `sqlmap` check against a URL
- **`nmap_vuln_scan`**: Run `nmap` vulnerability NSE scripts against a host

## Configuration & Limits

- **Tool timeout**: 60 seconds (120 seconds for vulnerability scans)
- **Max output**: 12,000 characters (truncated if exceeded)
- **Max buffer**: 10 MB per execution
- **Options constraints**: Commands enforce strict argument whitelisting to prevent abuse

## Security & Authorization

⚠️ **Important**: Run scans only on systems you own or have explicit written permission to test.

- The image uses a slim base and runs as a non-root user.
- The server limits command arguments and output size to reduce abuse and accidental overload.
- All tool executions are bounded by timeouts and resource constraints.
- Environment variables default to listening on all interfaces (`0.0.0.0`); restrict to `127.0.0.1` for local-only access.

## Development

### Project structure

```
.
├── Dockerfile          # Container definition
├── package.json        # Node.js dependencies & metadata
├── README.md           # This file
└── src/
    └── server.js       # MCP server implementation
```

### License & Disclaimer

Use responsibly. The authors are not responsible for misuse of this software. Ensure all scans are authorized.
