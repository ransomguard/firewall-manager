#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>

#include "utils.h"

#pragma comment(lib, "Ws2_32.lib")



namespace Ransom0 {
    namespace Firewall {
        namespace Utils {
            bool Ipv4ToString(uint32_t ip, std::string& outStr) {
                // WFP에서 사용하던 Host Byte Order(ntohl된 값)를 다시 Network Byte Order로 뒤집음
                uint32_t netIp = htonl(ip); 
                char buf[INET_ADDRSTRLEN] = { 0 };
                
                // inet_ntop는 성공 시 버퍼 포인터를, 실패 시 nullptr을 반환함
                if (inet_ntop(AF_INET, &netIp, buf, INET_ADDRSTRLEN) != nullptr) {
                    outStr = buf;
                    return true;
                }
                return false;
            }

            bool Ipv6ToString(const std::array<uint8_t, 16>& ip, std::string& outStr) {
                char buf[INET6_ADDRSTRLEN] = { 0 };
                
                // IPv6는 이미 Network Byte Order 상태이므로 그대로 넘김
                if (inet_ntop(AF_INET6, ip.data(), buf, INET6_ADDRSTRLEN) != nullptr) {
                    outStr = buf;
                    return true;
                }
                return false;
            }

            bool ParseIpv4(const std::string& ipStr, uint32_t& outIp) {
                IN_ADDR addr = { 0 };
                // 문자열을 네트워크 바이트 배열로 변환
                if (inet_pton(AF_INET, ipStr.c_str(), &addr) == 1) {
                    // WFP는 IPv4를 Host Byte Order(ntohl)로 요구합니다.
                    outIp = ntohl(addr.S_un.S_addr);
                    return true;
                }
                return false;
            }

            bool ParseIpv6(const std::string& ipStr, std::array<uint8_t, 16>& outIp) {
                IN6_ADDR addr = { 0 };
                // 문자열을 네트워크 바이트 배열(16바이트)로 변환
                if (inet_pton(AF_INET6, ipStr.c_str(), &addr) == 1) {
                    // WFP의 FWP_BYTE_ARRAY16은 Network Byte Order 그대로 사용합니다.
                    std::memcpy(outIp.data(), addr.u.Byte, 16);
                    return true;
                }
                return false;
            }

            bool ResolveDomainToIps(
                const std::string& domain,
                std::vector<uint32_t>& outIpv4s,
                std::vector<std::array<uint8_t, 16>>& outIpv6s
            ) {
                struct addrinfo hints = { 0 };
                struct addrinfo* res = nullptr;

                hints.ai_family = AF_UNSPEC;     // IPv4와 IPv6 모두 한 번에 조회
                hints.ai_socktype = SOCK_STREAM;

                // DNS 서버에 질의하여 도메인의 IP 목록을 받아옴
                if (getaddrinfo(domain.c_str(), NULL, &hints, &res) != 0) {
                    return false; // 도메인을 찾을 수 없음
                }

                bool found = false;

                // 반환된 링크드 리스트를 순회하며 IPv4 / IPv6 구분하여 추출
                for (struct addrinfo* ptr = res; ptr != nullptr; ptr = ptr->ai_next) {
                    if (ptr->ai_family == AF_INET) {
                        struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)ptr->ai_addr;

                        // IPv4: 빅 엔디안을 호스트 바이트 오더(리틀 엔디안)로 변환
                        uint32_t hostIp = ntohl(sockaddr_ipv4->sin_addr.S_un.S_addr);
                        outIpv4s.push_back(hostIp);
                        found = true;
                    }
                    else if (ptr->ai_family == AF_INET6) {
                        struct sockaddr_in6* sockaddr_ipv6 = (struct sockaddr_in6*)ptr->ai_addr;

                        // IPv6: 네트워크 바이트 오더 그대로 16바이트 복사
                        std::array<uint8_t, 16> ipv6Bytes = { 0 };
                        std::memcpy(ipv6Bytes.data(), sockaddr_ipv6->sin6_addr.u.Byte, 16);
                        outIpv6s.push_back(ipv6Bytes);
                        found = true;
                    }
                }

                freeaddrinfo(res); // 메모리 해제
                return found;
            }
        }
    }
}
