import Foundation
import DNSProxy

let redirectIP = ProcessInfo.processInfo.environment["DNS_REDIRECT_IP"] ?? "192.168.100.1"

let blockedDomains: Set<String> = [
    "doubleclick.net",
    "googleadservices.com",
    "://example.com"
]

let port = UInt16(ProcessInfo.processInfo.environment["DNS_PORT"] ?? "8353") ?? 8353

let server = DNSProxyServer(
    port: port,
    redirectIP: redirectIP,
    blocklist: Blocklist(domains: blockedDomains)
)
server.start()
