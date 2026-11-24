import Testing
import Foundation
@testable import DNSProxy

// MARK: - Helpers

/// Builds a minimal valid DNS query packet for the given domain and question type.
func makeQuery(domain: String, qtype: UInt16 = 1, qclass: UInt16 = 1, id: UInt16 = 0x1234, rd: Bool = true) -> [UInt8] {
    var pkt: [UInt8] = [
        UInt8(id >> 8), UInt8(id & 0xFF),
        0x01, UInt8(rd ? 0x00 : 0x00),
        0x00, 0x01,   // QDCOUNT = 1
        0x00, 0x00,   // ANCOUNT
        0x00, 0x00,   // NSCOUNT
        0x00, 0x00,   // ARCOUNT
    ]
    for label in domain.split(separator: ".") {
        let labelBytes = Array(label.utf8)
        pkt.append(UInt8(labelBytes.count))
        pkt.append(contentsOf: labelBytes)
    }
    pkt.append(0) // root label
    withUnsafeBytes(of: qtype.bigEndian) { pkt.append(contentsOf: $0) }
    withUnsafeBytes(of: qclass.bigEndian) { pkt.append(contentsOf: $0) }
    return pkt
}

// MARK: - DNSPacket.extractDomain

@Suite("DNSPacket.extractDomain") struct ExtractDomainTests {
    @Test func extractsSimpleDomain() {
        let query = makeQuery(domain: "example.com")
        #expect(DNSPacket.extractDomain(from: query) == "example.com")
    }

    @Test func extractsMultiLabelSubdomain() {
        let query = makeQuery(domain: "sub.api.example.com")
        #expect(DNSPacket.extractDomain(from: query) == "sub.api.example.com")
    }

    @Test func lowercasesUppercaseDomain() {
        let query = makeQuery(domain: "EXAMPLE.COM")
        #expect(DNSPacket.extractDomain(from: query) == "example.com")
    }

    @Test func singleLabelDomain() {
        let query = makeQuery(domain: "localhost")
        #expect(DNSPacket.extractDomain(from: query) == "localhost")
    }

    @Test func tooShortPacketReturnsNil() {
        #expect(DNSPacket.extractDomain(from: [0, 1, 2, 3, 4]) == nil)
    }

    @Test func truncatedMidLabelReturnsNil() {
        var query = makeQuery(domain: "example.com")
        query.removeLast(8) // cut the packet in the middle of the last label
        #expect(DNSPacket.extractDomain(from: query) == nil)
    }

    @Test func compressionPointerReturnsNil() {
        var query = makeQuery(domain: "example.com")
        query[12] = 0xC0 // pretend first label is a compression pointer
        #expect(DNSPacket.extractDomain(from: query) == nil)
    }
}

// MARK: - DNSPacket.makeBlockedResponse

@Suite("DNSPacket.makeBlockedResponse") struct BlockedResponseTests {
    @Test func setsResponseFlagsAndNXDomain() {
        let response = DNSPacket.makeBlockedResponse(from: makeQuery(domain: "example.com"))
        #expect(response != nil)
        #expect(response![2] == 0x81) // QR=1, RD=1
        #expect(response![3] == 0x83) // RA=1, RCODE=3 (NXDOMAIN)
    }

    @Test func zerosAllRecordCounts() {
        let response = DNSPacket.makeBlockedResponse(from: makeQuery(domain: "example.com"))!
        for i in 6..<12 {
            #expect(response[i] == 0)
        }
    }

    @Test func questionSectionPreserved() {
        let query = makeQuery(domain: "example.com")
        let response = DNSPacket.makeBlockedResponse(from: query)!
        #expect(Array(response[12...]) == Array(query[12...]))
    }

    @Test func shortQueryReturnsNil() {
        #expect(DNSPacket.makeBlockedResponse(from: [0, 1, 2, 3]) == nil)
    }
}

// MARK: - DNSPacket.redirectDomain

@Suite("DNSPacket.redirectDomain") struct RedirectDomainTests {
    @Test func aRecordResponseContainsRedirectARecord() {
        let query = makeQuery(domain: "example.com")
        let response = DNSPacket.redirectDomain(from: query, redirectIP: "192.168.100.1")
        #expect(response != nil)
        let bytes = response!

        // Header: QR=1, RD=1, RA=1, RCODE=0 (NOERROR)
        #expect(bytes[2] == 0x81)
        #expect(bytes[3] == 0x80)
        // Question count 1, answer count 1, no authority/additional
        #expect(bytes[4] == 0 && bytes[5] == 1)
        #expect(bytes[6] == 0 && bytes[7] == 1)
        #expect(bytes[8] == 0 && bytes[9] == 0)
        #expect(bytes[10] == 0 && bytes[11] == 0)

        // Header (12) + question section (13 name + 4 type/class) = 29
        #expect(bytes.count == 29 + 16)
        let a = 29
        // Answer record: name pointer, type A, class IN, TTL 60, rdlength 4, RDATA
        #expect(bytes[a] == 0xC0 && bytes[a + 1] == 0x0C)
        #expect(bytes[a + 2] == 0x00 && bytes[a + 3] == 0x01)
        #expect(bytes[a + 4] == 0x00 && bytes[a + 5] == 0x01)
        #expect(Array(bytes[a + 6..<a + 10]) == [0, 0, 0, 60])
        #expect(bytes[a + 10] == 0 && bytes[a + 11] == 4)
        #expect(Array(bytes.suffix(4)) == [192, 168, 100, 1])
    }

    @Test func differentRedirectIP() {
        let response = DNSPacket.redirectDomain(from: makeQuery(domain: "example.com"), redirectIP: "10.0.0.5")!
        #expect(Array(response.suffix(4)) == [10, 0, 0, 5])
    }

    @Test func nonAQueryGetsNoAnswerRecord() {
        let response = DNSPacket.redirectDomain(from: makeQuery(domain: "example.com", qtype: 28), redirectIP: "192.168.100.1")
        #expect(response != nil)
        let bytes = response!
        // Header says zero answers and packet ends right after the question section
        #expect(bytes[6] == 0 && bytes[7] == 0)
        #expect(bytes.count == 29)
    }

    @Test func invalidRedirectIPReturnsNil() {
        #expect(DNSPacket.redirectDomain(from: makeQuery(domain: "example.com"), redirectIP: "not.an.ip") == nil)
    }

    @Test func shortQueryReturnsNil() {
        #expect(DNSPacket.redirectDomain(from: [0, 1, 2, 3], redirectIP: "192.168.100.1") == nil)
    }

    @Test func queryMissingQTypeReturnsNil() {
        var query = makeQuery(domain: "example.com")
        query.removeLast(2) // cut qtype/qclass
        #expect(DNSPacket.redirectDomain(from: query, redirectIP: "192.168.100.1") == nil)
    }
}

// MARK: - Blocklist

@Suite("Blocklist") struct BlocklistTests {
    let blocklist = Blocklist(domains: ["doubleclick.net", "://example.com"])

    @Test func exactMatchIsBlocked() {
        #expect(blocklist.isBlocked("doubleclick.net"))
    }

    @Test func subdomainIsBlocked() {
        #expect(blocklist.isBlocked("ads.doubleclick.net"))
    }

    @Test func deepSubdomainIsBlocked() {
        #expect(blocklist.isBlocked("a.b.doubleclick.net"))
    }

    @Test func unknownDomainIsNotBlocked() {
        #expect(!blocklist.isBlocked("example.org"))
    }

    @Test func similarPrefixIsNotBlocked() {
        #expect(!blocklist.isBlocked("notdoubleclick.net"))
    }

    @Test func suffixWithoutDotIsNotBlocked() {
        #expect(!blocklist.isBlocked("xdoubleclick.net"))
    }

    @Test func emptyBlocklistBlocksNothing() {
        let empty = Blocklist(domains: [])
        #expect(!empty.isBlocked("anything.com"))
    }
}
