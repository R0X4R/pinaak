<p align="center">
  <img src="images/thumbnail.png" alt="Pinaak image">
</p>

<p align="center">
  <a href="#why-i-built-pinaak">Why I Built Pinaak</a> •
  <a href="#key-capabilities">Key Capabilities</a> •
  <a href="#discovery-techniques">Discovery Techniques</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#installation">Installation</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#usage">Usage</a> •
  <a href="#credits--acknowledgements">Credits</a>
</p>

## Why I Built Pinaak

During bug bounty hunting and security assessments, almost every high-value target sits behind Cloudflare, Akamai, CloudFront, or Fastly. When you test a domain through a CDN or WAF, your requests get inspected, rate limited, or blocked by generic rules.

Finding the real origin IP changes everything. Once you locate the origin server, you connect directly to the backend IP, bypass the WAF completely, and uncover vulnerabilities that the proxy would normally hide.

I wanted a single workflow that gathers candidate IPs through certificates, favicon hashes, historical DNS, and mail records, accepts input subdomains from existing recon pipelines, and actively confirms the real origin server by probing candidate IPs directly with the target Host header.

This tool is totally created by vibe coding. My goal was simple: build a fast, practical origin IP discovery tool that runs every proven technique in one pass and gives you verified results.

## Key Capabilities

All in one discovery. Pinaak queries certificate search engines, calculates favicon MurmurHash3 signatures, inspects historical DNS, and analyzes MX and SPF records in a single run.

Pipeline ready. Pinaak accepts subdomains piped directly from stdin or passed via a file, allowing direct integration with existing reconnaissance workflows.

True origin verification. Pinaak connects directly to candidate IPs on ports 443 and 80 with the target Host header and TLS SNI, compares the response title against the public baseline, and discards unconfirmed candidates.

Cloud origin preservation. Pinaak isolates and filters CDN and WAF edge IP addresses while retaining legitimate cloud virtual machines in the candidate pool.

## Discovery Techniques

| Technique | Description | Data Sources |
| :--- | :--- | :--- |
| **Certificate Search** | Searches internet scanners for SSL certificates matching the target domain. | Censys v2, Shodan |
| **Favicon Hashing** | Computes the 32-bit MurmurHash3 of the target favicon.ico and finds identical hosts. | Shodan, FOFA |
| **DNS History** | Queries historical A records from before the domain moved behind a proxy. | SecurityTrails |
| **Mail & SPF Records** | Resolves MX hosts and extracts IPv4 directives from SPF TXT records. | dnsx (MX, TXT) |
| **Subdomain Resolution** | Resolves user-supplied subdomains concurrently and filters out CDN IP ranges. | dnsx, cdncheck |
| **Active Verification** | Probes candidate IPs directly with Host headers and TLS SNI to confirm the origin application. | Direct HTTP/HTTPS |

## How It Works

```mermaid
flowchart TD
    classDef step fill:#161b22,stroke:#30363d,stroke-width:1.5px,color:#e6edf3;
    classDef engine fill:#1f242c,stroke:#58a6ff,stroke-width:2px,color:#58a6ff;
    classDef finding fill:#1b2a1a,stroke:#3fb950,stroke-width:2px,color:#3fb950;
    classDef safe fill:#21262d,stroke:#8b949e,stroke-width:1px,color:#8b949e;

    IN["Target Input<br>(Domain via -d, subdomains via -l or stdin)"]:::step --> BL["Capture Baseline<br>(Fetch public status and title through CDN)"]:::step
    BL --> DISCO["Discovery Modules<br>(Certs, Favicon, DNS History, Mail, Subdomains)"]:::step
    DISCO --> CDN["CDN Range Filter<br>(cdncheck drops Cloudflare, Akamai, Fastly edges)"]:::engine
    CDN --> VER["Active Verification Engine<br>(Direct IP probe with Host header and SNI)"]:::engine

    VER -->|Signature Matches Baseline| ORIGIN["Verified Origin IP<br>[SUC] target.com -> IP (method)"]:::finding
    VER -->|Mismatch or Error Block| DISCARD["Filtered Candidate<br>(Discarded with zero false positives)"]:::safe
```

## Installation
### Install via Go

```bash
go install -v github.com/R0X4R/pinaak@latest
```

### Build from Source

```bash
git clone https://github.com/R0X4R/pinaak.git && cd pinaak && go install -v
```

### Pre-built Binaries

Pre-compiled binaries are generated on every push to main and for every tagged release.

Download the archive for your operating system and architecture from the [Releases](https://github.com/R0X4R/pinaak/releases) page.

On Linux and macOS:

```bash
tar -xzf pinaak_latest_linux_amd64.tar.gz && chmod +x pinaak && sudo mv pinaak /usr/local/bin/
```

On Windows, extract `pinaak_latest_windows_amd64.zip` and add `pinaak.exe` to your PATH.

### Docker

Pinaak is published as a multi-architecture container supporting both `linux/amd64` and `linux/arm64`.

Pull the image from GitHub Container Registry or Docker Hub:

```bash
docker pull ghcr.io/r0x4r/pinaak:latest
# or
docker pull r0x4r/pinaak:latest
```

Run directly against a target domain:

```bash
docker run --rm -i ghcr.io/r0x4r/pinaak -d target.com
```

Pipe subdomains from stdin into the container:

```bash
cat subdomains.txt | docker run --rm -i ghcr.io/r0x4r/pinaak
```

Chain directly with subfinder:

```bash
subfinder -d target.com -silent | docker run --rm -i ghcr.io/r0x4r/pinaak -d target.com
```

Mount your local configuration file for API keys:

```bash
docker run --rm -i -v ~/.config/pinaak:/root/.config/pinaak ghcr.io/r0x4r/pinaak -d target.com
```

Mount your current working directory to save results:

```bash
docker run --rm -i -v $(pwd):/data ghcr.io/r0x4r/pinaak -d target.com -o /data/results.txt
```

## Configuration

Pinaak works out of the box with passive DNS, mail records, and subdomain resolution. To enable search engine queries, add your API keys to `~/.config/pinaak/config.yaml`:

```yaml
shodan-key: "YOUR_SHODAN_KEY"
censys-id: "YOUR_CENSYS_ID"
censys-secret: "YOUR_CENSYS_SECRET"
fofa-email: "YOUR_FOFA_EMAIL"
fofa-key: "YOUR_FOFA_KEY"
securitytrails-key: "YOUR_SECURITYTRAILS_KEY"
```

You can also export environment variables:

```bash
export SHODAN_API_KEY="YOUR_KEY"
export CENSYS_API_ID="YOUR_ID"
export CENSYS_API_SECRET="YOUR_SECRET"
export FOFA_EMAIL="YOUR_EMAIL"
export FOFA_KEY="YOUR_KEY"
export SECURITYTRAILS_API_KEY="YOUR_KEY"
```

## Usage

```bash
pinaak -h
```

### Flags Reference

| Flag | Shorthand | Default | Description |
| :--- | :--- | :--- | :--- |
| `-domain` | `-d` | `""` | Target domain to discover origin IP for |
| `-list` | `-l` | `""` | File containing already-known subdomains (or auto-read from stdin) |
| `-config` | | `""` | Configuration file path (default: `~/.config/pinaak/config.yaml`) |
| `-threads` | `-t` | `25` | Number of concurrent workers |
| `-timeout` | | `10` | Network timeout in seconds |
| `-skip-verify` | | `false` | Skip HTTP Host header verification on candidate IPs |
| `-output` | `-o` | `""` | File path to save discovered results |
| `-json` | `-j` | `false` | Output results in JSON format |
| `-silent` | `-s` | `false` | Suppress non-essential status logs |
| `-no-color` | `-nc` | `false` | Disable ANSI color output |
| `-shodan-key` | | `""` | Shodan API key for favicon and cert lookups |
| `-censys-id` | | `""` | Censys API ID for certificate search |
| `-censys-secret` | | `""` | Censys API secret for certificate search |
| `-fofa-email` | | `""` | FOFA account email |
| `-fofa-key` | | `""` | FOFA API key |
| `-securitytrails-key` | | `""` | SecurityTrails API key for historical DNS records |

### Examples

Find origin IP for a single domain:

```bash
pinaak -d target.com
```

Pipe subdomains directly from subfinder:

```bash
subfinder -d target.com -silent | pinaak -d target.com
```

Pipe subdomains from stdin without flags:

```bash
cat subdomains.txt | pinaak
```

Provide a list of already-known subdomains:

```bash
pinaak -l subdomains.txt
```

Combine target domain with a subdomains list:

```bash
pinaak -d target.com -l subdomains.txt
```

Save results to a file in JSON format:

```bash
pinaak -d target.com -j -o results.json
```

Run with custom concurrency and timeout:

```bash
pinaak -d target.com -t 50 -timeout 5
```

## Credits & Acknowledgements

Pinaak relies on open-source libraries:

[ProjectDiscovery cdncheck](https://github.com/projectdiscovery/cdncheck) provides CDN and WAF CIDR range detection.
[ProjectDiscovery dnsx](https://github.com/projectdiscovery/dnsx) handles concurrent DNS resolution.
[ProjectDiscovery goflags](https://github.com/projectdiscovery/goflags) provides CLI flag parsing and configuration management.
[Fatih Arslan color](https://github.com/fatih/color) formats terminal color output.
[Murmur3](https://github.com/spaolacci/murmur3) provides Shodan-compatible favicon hash calculation.
[sqlmapproject](https://github.com/sqlmapproject/sqlmap) provides the browser User-Agent dataset.
