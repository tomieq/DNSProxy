import Foundation

#if canImport(Darwin)
import Darwin
let SOCK_DGRAM_VALUE = SOCK_DGRAM
#elseif canImport(Glibc)
import Glibc
let SOCK_DGRAM_VALUE = Int32(SOCK_DGRAM.rawValue)
#endif

/// Pure POSIX UDP DNS proxy: forwards queries to an upstream server,
/// answering hijacked domains with a redirect A record and blocked domains with NXDOMAIN.
public struct DNSProxyServer {
    public let port: UInt16
    public let upstreamIP: String
    public let blocklist: Blocklist
    public let hijacklist: HijackList

    public init(port: UInt16, upstreamIP: String = "8.8.8.8", blocklist: Blocklist, hijacklist: HijackList = HijackList(entries: [:])) {
        self.port = port
        self.upstreamIP = upstreamIP
        self.blocklist = blocklist
        self.hijacklist = hijacklist
    }

    public func start() {
        let serverSock = socket(AF_INET, SOCK_DGRAM_VALUE, 0)
        guard serverSock >= 0 else { fatalError("Failed to create socket") }

        var reuse: Int32 = 1
        setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var serverAddr = sockaddr_in()
        serverAddr.sin_family = sa_family_t(AF_INET)
        serverAddr.sin_port = port.bigEndian
        serverAddr.sin_addr.s_addr = INADDR_ANY.bigEndian

        let bindResult = withUnsafePointer(to: &serverAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(serverSock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult >= 0 else { fatalError("Failed to bind to port \(port)") }

        // Configure upstream address
        var upstreamAddr = sockaddr_in()
        upstreamAddr.sin_family = sa_family_t(AF_INET)
        upstreamAddr.sin_port = UInt16(53).bigEndian
        inet_pton(AF_INET, upstreamIP, &upstreamAddr.sin_addr)

        print("Pure Swift DNS Proxy listening on UDP port \(port)...")

        var buffer = [UInt8](repeating: 0, count: 512)
        var clientAddr = sockaddr_in()
        var clientAddrLen = socklen_t(MemoryLayout<sockaddr_in>.size)

        while true {
            let bytesRead = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(serverSock, &buffer, buffer.count, 0, $0, &clientAddrLen)
                }
            }
            guard bytesRead > 0 else { continue }

            let query = Array(buffer[0..<bytesRead])
            let domain = DNSPacket.extractDomain(from: query) ?? "unknown"
            let currentClient = clientAddr

            if let hijackIP = hijacklist.redirectIP(for: domain) {
                print("[HIJACKED] \(domain) -> \(hijackIP)")
                if let redirectReply = DNSPacket.redirectDomain(from: query, redirectIP: hijackIP) {
                    sendUDP(sock: serverSock, data: redirectReply, to: currentClient)
                }
                continue
            }

            if blocklist.isBlocked(domain) {
                print("[BLOCKED] \(domain)")
                if let blockedReply = DNSPacket.makeBlockedResponse(from: query) {
                    sendUDP(sock: serverSock, data: blockedReply, to: currentClient)
                }
                continue
            }

            print("[ALLOWED] \(domain)")

            // Forward to upstream concurrently using GCD
            DispatchQueue.global().async {
                let upstreamSock = socket(AF_INET, SOCK_DGRAM_VALUE, 0)
                guard upstreamSock >= 0 else { return }
                defer { close(upstreamSock) }

                // Set 2-second receive timeout so threads don't hang on dropped packets
                var timeout = timeval(tv_sec: 2, tv_usec: 0)
                setsockopt(upstreamSock, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

                sendUDP(sock: upstreamSock, data: query, to: upstreamAddr)

                var replyBuffer = [UInt8](repeating: 0, count: 512)
                let replyLen = recvfrom(upstreamSock, &replyBuffer, replyBuffer.count, 0, nil, nil)
                if replyLen > 0 {
                    sendUDP(sock: serverSock, data: Array(replyBuffer[0..<replyLen]), to: currentClient)
                }
            }
        }
    }
}

func sendUDP(sock: Int32, data: [UInt8], to addr: sockaddr_in) {
    var target = addr
    withUnsafePointer(to: &target) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            _ = sendto(sock, data, data.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
}
