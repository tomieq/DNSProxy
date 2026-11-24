import Foundation

/// A map of domains to the IP address they should be redirected to.
/// A query matches if the domain equals an entry or is a subdomain of it.
public struct HijackList {
    public let entries: [String: String]

    public init(entries: [String: String]) {
        self.entries = entries
    }

    public func redirectIP(for domain: String) -> String? {
        let matches = entries.filter { domain == $0.key || domain.hasSuffix("." + $0.key) }
        guard !matches.isEmpty else { return nil }
        // Longest (most specific) entry wins
        return matches.max { $0.key.count < $1.key.count }!.value
    }
}
