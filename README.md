# DNSProxy

A pure Swift DNS proxy written with raw POSIX UDP sockets — no third-party dependencies.

It listens on a UDP port and forwards DNS queries to an upstream resolver (Google's `8.8.8.8` by default). It intercepts queries for:
- **hijacked** domains — answered with a forged A record pointing to the per-domain redirect IP.
- **blocked** domains — answered with NXDOMAIN, so the client treats the domain as non-existent.

## How it works

1. A client sends a DNS query to the proxy (UDP).
2. The queried domain is extracted from the packet and checked against the hijacklist, then the blocklist.
   - **Hijacked** → the proxy replies directly with a forged response: the question section is kept and an A record pointing to the domain's configured IP (TTL 60s) is appended. No upstream call is made.
   - **Blocked** → the proxy replies directly with NXDOMAIN (RCODE 3), all record counts zeroed. No upstream call is made.
   - **Allowed** → the query is forwarded to the upstream resolver and its answer is relayed back to the client.
3. Non-A queries (e.g. AAAA) for hijacked domains get an empty NOERROR response (no record).

Both lists match exact domains and all of their subdomains (`ads.doubleclick.net` matches when `doubleclick.net` is listed). When a domain matches several hijacklist entries, the most specific (longest) one wins.

Domains are defined in `Sources/DNSProxyCLI/main.swift`:

```swift
let blockedDomains: Set<String> = [
    "doubleclick.net",
    "googleadservices.com",
    "://example.com"
]

let hijackedDomains: [String: String] = [
    "hijacked.example.com": "192.168.100.50"
]
```

## Project layout

```
Sources/
  DNSProxy/            # library: all logic, unit-testable
    DNSPacket.swift    #   packet parsing: extractDomain, redirectDomain, makeBlockedResponse
     Blocklist.swift    #   domain blocklist + subdomain matching
     HijackList.swift   #   domain -> IP redirections + subdomain matching
     DNSProxyServer.swift #  POSIX UDP server loop, upstream forwarding
  DNSProxyCLI/
    main.swift         # entry point: env config, starts the server
Tests/
  DNSProxyTests/       # swift-testing unit tests
Dockerfile             # multi-stage build for Raspberry Pi / x86_64 Linux
```

## Requirements

- Swift 6.1+ (Xcode 16.3+ on macOS)
- Docker (optional, for the container build)

## Setup and run

Build and run locally:

```bash
swift build
.build/debug/DNSProxyCLI
```

Or run directly:

```bash
swift run DNSProxyCLI
```

Configuration via environment variables:

| Variable           | Default         | Description                          |
|--------------------|-----------------|--------------------------------------|
| `DNS_PORT`         | `8353`          | UDP port the proxy listens on        |

Example:

```bash
DNS_PORT=8353 swift run DNSProxyCLI
```

> Note: binding port 53 requires root (or `sudo`).

### Docker

```bash
docker build -t dnsproxy .

# run on the standard DNS port (requires NET_BIND_SERVICE for port 53)
sudo docker run --rm -it --cap-add=NET_BIND_SERVICE -p 53:53/udp dnsproxy

# or on an unprivileged port
docker run --rm -it -e DNS_PORT=8353 -p 8353:8353/udp dnsproxy
```

The Dockerfile cross-builds for Linux (aarch64 for Raspberry Pi, x86_64 for Intel/AMD).

## Testing with dig

Start the proxy (default port `8353`), then in another terminal:

**Hijacked domain → returns its configured IP:**

```bash
dig @127.0.0.1 -p 8353 hijacked.example.com +short
# 192.168.100.50
```

**Hijacked subdomain → also redirected:**

```bash
dig @127.0.0.1 -p 8353 www.hijacked.example.com +short
# 192.168.100.50
```

**Blocked domain → NXDOMAIN:**

```bash
dig @127.0.0.1 -p 8353 doubleclick.net +short
# (empty)

dig @127.0.0.1 -p 8353 doubleclick.net
# STATUS: NXDOMAIN
```

**Blocked subdomain → also NXDOMAIN:**

```bash
dig @127.0.0.1 -p 8353 ads.doubleclick.net +short
# (empty)
```

**Allowed domain → forwarded to 8.8.8.8 and relayed:**

```bash
dig @127.0.0.1 -p 8353 example.com +short
# 93.184.215.14 (or whatever Google returns)
```

**AAAA query for a hijacked domain → NOERROR with no answer:**

```bash
dig @127.0.0.1 -p 8353 hijacked.example.com AAAA +short
# (empty)
```

If the proxy runs in Docker on the host's port 53, drop the `-p` flag: `dig @127.0.0.1 doubleclick.net +short`.

## Unit tests

The packet/blocklist logic lives in the `DNSProxy` library target and is covered by swift-testing tests:

```bash
swift test
```

```
Test run with 31 tests in 5 suites passed
```

Covered: domain extraction (multi-label, upper/lower case, malformed/compressed packets), NXDOMAIN response flags, redirect A-record layout (TTL, RDLENGTH, RDATA), non-A queries, blocklist subdomain matching, and hijacklist matching (exact, subdomain, most-specific entry wins).
