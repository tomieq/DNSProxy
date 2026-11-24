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

}
