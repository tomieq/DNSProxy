import Foundation

/// A set of domains whose DNS queries should be intercepted.
/// A query matches if the domain equals a blocked entry or is a subdomain of it.
public struct Blocklist {
    public let domains: Set<String>

    public init(domains: Set<String>) {
        self.domains = domains
    }

    public func isBlocked(_ domain: String) -> Bool {
        domains.contains { domain == $0 || domain.hasSuffix("." + $0) }
    }
}
