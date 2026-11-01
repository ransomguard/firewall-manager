#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>
#include <cctype>
#include <algorithm>

#include "utils.h"

#pragma comment(lib, "Ws2_32.lib")



namespace {
    // 내부 공통 헬퍼: 앞뒤 공백 제거
    std::string Trim(const std::string& str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = str.find_last_not_of(" \t\r\n");
        return str.substr(start, end - start + 1);
    }

    // 내부 공통 헬퍼: 1~65535 포트 번호 파싱
    bool ParsePort(const std::string& portStr, uint16_t& outPort) {
        if (portStr.empty()) return false;
        try {
            size_t idx = 0;
            int p = std::stoi(portStr, &idx);
            if (idx == portStr.length() && p > 0 && p <= 65535) {
                outPort = static_cast<uint16_t>(p);
                return true;
            }
        } catch (...) {}
        return false;
    }

    // 내부 공통 헬퍼: 슬래시('/') 기준 문자열 분리
    bool SplitBySlash(const std::string& str, std::string& outLeft, std::string& outRight) {
        size_t pos = str.find('/');
        if (pos == std::string::npos) return false;
        outLeft = str.substr(0, pos);
        outRight = str.substr(pos + 1);
        return !outLeft.empty() && !outRight.empty();
    }
}



namespace Ransom0 {
    namespace Firewall {
        namespace Utils {
            bool Ipv4ToString(uint32_t ip, std::string& outStr) {
                // Host Byte Order -> Network Byte Order
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

                // IPv6는 이미 Network Byte Order 상태이므로 그대로 변환
                if (inet_ntop(AF_INET6, ip.data(), buf, INET6_ADDRSTRLEN) != nullptr) {
                    outStr = buf;
                    return true;
                }
                return false;
            }

            uint8_t MaskToPrefixV4(uint32_t mask) {
                uint8_t prefix = 0;
                uint32_t m = mask;
                while (m & 0x80000000UL) {
                    prefix++;
                    m <<= 1;
                }
                return prefix;
            }

            bool ParseIpv4(const std::string& ipStr, uint32_t& outIp) {
                IN_ADDR addr = { 0 };
                // 문자열을 네트워크 바이트 배열로 변환
                if (inet_pton(AF_INET, ipStr.c_str(), &addr) == 1) {
                    // WFP는 IPv4를 Host Byte Order(ntohl)로 요구
                    outIp = ntohl(addr.S_un.S_addr);
                    return true;
                }
                return false;
            }

            bool ParseIpv6(const std::string& ipStr, std::array<uint8_t, 16>& outIp) {
                IN6_ADDR addr = { 0 };
                // 문자열을 네트워크 바이트 배열(16바이트)로 변환
                if (inet_pton(AF_INET6, ipStr.c_str(), &addr) == 1) {
                    // WFP의 FWP_BYTE_ARRAY16은 Network Byte Order 사용
                    std::memcpy(outIp.data(), addr.u.Byte, 16);
                    return true;
                }
                return false;
            }

            bool ParseCidrV4(const std::string& cidrStr, uint32_t& outIp, uint32_t& outMask) {
                std::string ipPart, suffix;
                if (!SplitBySlash(cidrStr, ipPart, suffix)) return false;

                uint32_t rawIp = 0;
                if (!ParseIpv4(ipPart, rawIp)) return false;

                // 서브넷 마스크(예: 255.255.255.0) 또는 프리픽스(예: 24) 처리
                if (suffix.find('.') != std::string::npos) {
                    uint32_t maskVal = 0;
                    if (!ParseIpv4(suffix, maskVal)) return false;
                    outMask = maskVal;
                } else {
                    try {
                        size_t idx = 0;
                        int prefix = std::stoi(suffix, &idx);
                        if (idx != suffix.length() || prefix < 0 || prefix > 32) return false;
                        outMask = (prefix == 0) ? 0 : (0xFFFFFFFFUL << (32 - prefix));
                    } catch (...) {
                        return false;
                    }
                }

                outIp = rawIp & outMask; // 네트워크 주소로 정규화
                return true;
            }

            bool ParseCidrV6(const std::string& cidrStr, std::array<uint8_t, 16>& outIp, uint8_t& outPrefix) {
                std::string ipPart, suffix;
                if (!SplitBySlash(cidrStr, ipPart, suffix)) return false;

                std::array<uint8_t, 16> rawIp = { 0 };
                if (!ParseIpv6(ipPart, rawIp)) return false;

                try {
                    size_t idx = 0;
                    int prefix = std::stoi(suffix, &idx);
                    if (idx != suffix.length() || prefix < 0 || prefix > 128) return false;
                    outPrefix = static_cast<uint8_t>(prefix);

                    outIp = rawIp;
                    // 프리픽스 초과 비트를 0으로 마스킹
                    for (int i = 0; i < 16; ++i) {
                        int bitOffset = i * 8;
                        if (prefix >= bitOffset + 8) {
                            // 전체 8비트 유지
                        } else if (prefix > bitOffset) {
                            int keepBits = prefix - bitOffset;
                            uint8_t mask = static_cast<uint8_t>(0xFF << (8 - keepBits));
                            outIp[i] &= mask;
                        } else {
                            outIp[i] = 0;
                        }
                    }
                    return true;
                } catch (...) {
                    return false;
                }
            }

            bool ParseUrl(const std::string& url, std::string& outHost, uint16_t& outPort) {
                size_t schemePos = url.find("://");
                if (schemePos == std::string::npos) return false;

                std::string scheme = url.substr(0, schemePos);
                std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });

                uint16_t defaultPort = 0;
                if (scheme == "http") defaultPort = 80;
                else if (scheme == "https") defaultPort = 443;
                else if (scheme == "ftp") defaultPort = 21;
                else if (scheme == "ssh") defaultPort = 22;

                size_t hostStart = schemePos + 3;
                size_t pathPos = url.find_first_of("/?#", hostStart);
                std::string authority = (pathPos == std::string::npos)
                    ? url.substr(hostStart)
                    : url.substr(hostStart, pathPos - hostStart);

                if (authority.empty()) return false;

                // userinfo (user:password@) 제거
                size_t atPos = authority.find('@');
                if (atPos != std::string::npos) {
                    authority = authority.substr(atPos + 1);
                }
                if (authority.empty()) return false;

                // [IPv6]:port 또는 [IPv6] 형태
                if (authority.front() == '[') {
                    size_t closeBracket = authority.find(']');
                    if (closeBracket == std::string::npos) return false;

                    outHost = authority.substr(1, closeBracket - 1);
                    if (closeBracket + 1 < authority.length()) {
                        if (authority[closeBracket + 1] != ':') return false;
                        if (!ParsePort(authority.substr(closeBracket + 2), outPort)) return false;
                    } else {
                        outPort = defaultPort;
                    }
                } else {
                    // host:port 또는 host (IPv6가 아니면서 단일 콜론이 존재하는 경우)
                    size_t colonPos = authority.rfind(':');
                    size_t firstColon = authority.find(':');
                    if (colonPos != std::string::npos && colonPos == firstColon) {
                        outHost = authority.substr(0, colonPos);
                        if (!ParsePort(authority.substr(colonPos + 1), outPort)) return false;
                    } else {
                        outHost = authority;
                        outPort = defaultPort;
                    }
                }

                return !outHost.empty();
            }

            bool SplitHostAndPort(const std::string& input, std::string& outHost, uint16_t& outPort) {
                std::string trimmed = Trim(input);
                if (trimmed.empty()) return false;

                // 1. URL 형식인 경우 자동 파싱
                if (ParseUrl(trimmed, outHost, outPort)) {
                    return true;
                }

                // 2. "*:port" 형태
                if (trimmed.rfind("*:", 0) == 0) {
                    if (ParsePort(trimmed.substr(2), outPort)) {
                        outHost = "*";
                        return true;
                    }
                    return false;
                }

                // 3. 순수 숫자만 입력된 경우 (예: "8080" -> 단독 포트 지정)
                bool allDigit = std::all_of(trimmed.begin(), trimmed.end(), [](unsigned char c) {
                    return std::isdigit(c);
                });
                if (allDigit && ParsePort(trimmed, outPort)) {
                    outHost = "*";
                    return true;
                }

                // 4. 대괄호 표기법 (예: "[fd00::1]:8080" 또는 "[fd00::/64]:8080")
                if (trimmed.front() == '[') {
                    size_t closePos = trimmed.find(']');
                    if (closePos == std::string::npos) return false;
                    outHost = trimmed.substr(1, closePos - 1);
                    if (closePos + 1 < trimmed.length()) {
                        if (trimmed[closePos + 1] != ':') return false;
                        if (!ParsePort(trimmed.substr(closePos + 2), outPort)) return false;
                    } else {
                        outPort = 0;
                    }
                    return !outHost.empty();
                }

                // 5. 콜론 개수에 따른 분기
                int colonCount = 0;
                for (char c : trimmed) {
                    if (c == ':') colonCount++;
                }

                // 콜론이 정확히 1개인 경우 -> "Host:Port"
                if (colonCount == 1) {
                    size_t colonPos = trimmed.find(':');
                    std::string h = trimmed.substr(0, colonPos);
                    if (ParsePort(trimmed.substr(colonPos + 1), outPort)) {
                        outHost = h;
                        return !outHost.empty();
                    }
                    return false;
                }

                // 콜론이 없거나 2개 이상인 경우 (단일 IPv4, 도메인, 순수 IPv6)
                outHost = trimmed;
                outPort = 0;
                return !outHost.empty();
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
