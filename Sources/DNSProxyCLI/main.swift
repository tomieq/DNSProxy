import Foundation
import DNSProxy

let blockedDomains: Set<String> = [
    "doubleclick.net",
    "googleadservices.com",
    "://example.com"
]

let hijackedDomains: [String: String] = [
    "hijacked.example.com": "192.168.100.50"
]

let port = UInt16(ProcessInfo.processInfo.environment["DNS_PORT"] ?? "8353") ?? 8353

let server = DNSProxyServer(
    port: port,
    blocklist: Blocklist(domains: blockedDomains),
    hijacklist: HijackList(entries: hijackedDomains)
)
server.start()
