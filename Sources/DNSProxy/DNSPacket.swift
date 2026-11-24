//
//  DNSPacket.swift
//  DNSProxy
// 
//  Created by: tomieq on 24/11/2026
//

import Foundation

struct DNSPacket {
    /// Extracts the queried domain name (e.g. "://example.com") from a raw DNS query
    static func extractDomain(from bytes: [UInt8]) -> String? {
        // DNS header is 12 bytes
        guard bytes.count > 12 else { return nil }
        
        var index = 12
        var labels: [String] = []
        
        while index < bytes.count {
            let length = Int(bytes[index])
            if length == 0 { break } // End of domain name
            
            // Guard against DNS compression pointers or malformed packets
            guard (length & 0xC0) == 0, index + length < bytes.count else { return nil }
            
            let labelBytes = bytes[(index + 1)...(index + length)]
            if let label = String(bytes: labelBytes, encoding: .utf8) {
                labels.append(label)
            }
            index += length + 1
        }
        
        return labels.isEmpty ? nil : labels.joined(separator: ".").lowercased()
    }
    
    /// Takes a raw DNS query packet and flips its header flags to return NXDOMAIN (Blocked)
    static func makeBlockedResponse(from query: [UInt8]) -> [UInt8]? {
        guard query.count >= 12 else { return nil }
        var response = query
        
        // Byte 2: Set QR bit (1 = Response) + preserve Opcode + set RD (Recursion Desired)
        response[2] = (query[2] & 0x78) | 0x81
        // Byte 3: Set RA (Recursion Available = 1) + RCODE 3 (NXDOMAIN)
        response[3] = 0x83
        
        // Zero out Answer, Authority, and Additional record counts (bytes 6-11)
        for i in 6..<12 { response[i] = 0 }
        
        return response
    }
    
    static func redirectDomain(from query: [UInt8], redirectIP: String = "192.168.100.1") -> [UInt8]? {
        // 1. Validate header (12 bytes) and find the end of the Question section
        guard query.count > 12 else { return nil }
        
        var index = 12
        while index < query.count {
            let length = Int(query[index])
            if length == 0 {
                index += 1 // Skip null terminator
                break
            }
            guard (length & 0xC0) == 0, index + length < query.count else { return nil }
            index += length + 1
        }
        
        // Ensure there are 4 bytes left for QTYPE (2 bytes) and QCLASS (2 bytes)
        guard index + 4 <= query.count else { return nil }
        let qtype = (UInt16(query[index]) << 8) | UInt16(query[index + 1])
        let questionEnd = index + 4

        // 2. Copy header + question section (strip any EDNS0 additional records from the query)
        var response = Array(query[0..<questionEnd])
        
        // Set Header Flags:
        response[2] = (query[2] & 0x78) | 0x81 // QR=1 (Response), preserve Opcode, RD=1
        response[3] = 0x80                    // RA=1 (Recursion Available), RCODE=0 (NOERROR)

        // Zero out Answer (bytes 6-7), Authority (bytes 8-9) and Additional (bytes 10-11) counts
        for i in 6..<12 { response[i] = 0 }

        // 3. Only attach an IPv4 Answer if the client asked for an A record (QTYPE == 1)
        guard qtype == 1 else { return response }

        // Parse the IPv4 string into 4 bytes
        var addr = in_addr()
        guard inet_pton(AF_INET, redirectIP, &addr) == 1 else { return nil }
        let ipBytes = withUnsafeBytes(of: addr.s_addr) { Array($0) }

        // Set Answer Count (ANCOUNT) = 1
        response[6] = 0x00
        response[7] = 0x01

        // 4. Append the 16-byte DNS Answer Resource Record
        response.append(contentsOf: [
            0xC0, 0x0C,             // Name: Compression pointer to offset 12 (the queried domain)
            0x00, 0x01,             // Type: A (IPv4 host address)
            0x00, 0x01,             // Class: IN (Internet)
            0x00, 0x00, 0x00, 0x3C, // TTL: 60 seconds
            0x00, 0x04              // RDLENGTH: 4 bytes
        ])
        response.append(contentsOf: ipBytes) // RDATA: e.g., [192, 168, 100, 1]

        return response
    }

}
