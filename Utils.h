#pragma once        // 중복 정의 에러 차단

#include <string>         // std::wstring, std::to_wstring
#include <vector>         // std::vector

namespace Ransom0 {
    namespace Firewall {
        namespace Utils {
            /**
             * @brief [공통 헬퍼 함수] CIDR 값을 서브넷 마스크 문자열로 변환
             * @param cidr CIDR 값 (0~32)
             * @return 서브넷 마스크 문자열 (예: 255.255.255.0)
             */
            inline std::wstring CidrToSubnetMask(int cidr) {
                // 1. 유효하지 않은 경우 32로 처리
                if (cidr < 0 || cidr > 32) return L"255.255.255.255";

                // 2. 명시적인 Unsigned Long 리터럴(UL) 사용
                unsigned long mask = (cidr == 0) ? 0 : (0xFFFFFFFFUL << (32 - cidr));

                // 3. wstringstream 대신 가볍고 빠른 swprintf_s 사용 (일관성 및 성능 향상)
                wchar_t buffer[16];
                swprintf_s(buffer, 16, L"%lu.%lu.%lu.%lu",
                        (mask >> 24) & 0xFF,
                        (mask >> 16) & 0xFF,
                        (mask >> 8) & 0xFF,
                        mask & 0xFF);

                return std::wstring(buffer);
            }

            /**
             * @brief [공통 헬퍼 함수] 서브넷 마스크를 CIDR 값으로 변환
             * @param maskStr 서브넷 마스크 문자열 (예: 255.255.255.0)
             * @return CIDR 값 (0~32)
             */
            inline int SubnetMaskToCidr(const std::wstring& maskStr) {
                int a, b, c, d;

                // 1. 파싱 실패 시 예외 처리
                if (swscanf_s(maskStr.c_str(), L"%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
                    return -1;
                }

                // 2. 0~255 범위를 벗어나는 오입력 방지
                if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) {
                    return -1;
                }

                unsigned long mask = (a << 24) | (b << 16) | (c << 8) | d;
                int cidr = 0;

                // 3. 최상위 비트(MSB)부터 1의 개수 카운팅
                while (mask > 0) {
                    if (mask & 0x80000000) {
                        cidr++;
                        mask <<= 1;
                    } else {
                        break; // 0이 등장하면 카운팅 중단
                    }
                }

                // 4. 중단된 시점에서 남은 비트가 있다면 유효하지 않은 마스크 (예: 255.0.255.0)
                if (mask != 0) {
                    return -1;
                }

                return cidr;
            }

            /**
             * @brief [공통 헬퍼 함수] IP 주소를 IP/서브넷마스크 형식으로 변환
             * @param ipStr IP 주소 문자열 (예: 192.168.0.0/24 or 192.168.0.0/255.255.255.0)
             * @return IP/서브넷마스크 문자열 (예: 192.168.0.0/255.255.255.0)
             */
            inline std::wstring NormalizeToSubnetMaskFormat(const std::wstring& ipStr) {
                // IPv6의 경우 (콜론 포함) 서브넷 마스크를 씌우지 않고 그대로 통과
                if (ipStr.find(L':') != std::wstring::npos) {
                    return ipStr;
                }

                size_t slashPos = ipStr.find(L'/');
                std::wstring ip = ipStr.substr(0, slashPos);
                std::wstring suffix = (slashPos != std::wstring::npos) ? ipStr.substr(slashPos + 1) : L"";

                std::wstring newSuffix;

                // 1. '/'가 없는 단일 IP인 경우 -> 기본값 255.255.255.255 적용
                if (suffix.empty()) {
                    newSuffix = L"255.255.255.255";
                }
                // 2. 뒤에 '.'이 포함된 경우 -> 이미 서브넷 마스크 형태이므로 그대로 사용
                else if (suffix.find(L'.') != std::wstring::npos) {
                    newSuffix = suffix;
                }
                // 3. CIDR 형태인 경우 -> 서브넷 마스크로 변환
                else {
                    int cidr = 32;
                    swscanf_s(suffix.c_str(), L"%d", &cidr); // 안전한 정수 파싱
                    newSuffix = CidrToSubnetMask(cidr);
                }

                return ip + L"/" + newSuffix;
            }

            /**
             * @brief [공통 헬퍼 함수] IP 주소를 IP/CIDR 형식으로 변환
             * @param ipStr IP 주소 문자열 (예: 192.168.0.0/24 or 192.168.0.0/255.255.255.0)
             * @return IP/CIDR 문자열 (예: 192.168.0.0/24)
             */
            inline std::wstring NormalizeToCidrFormat(const std::wstring& ipStr) {
                // IPv6의 경우 (콜론 포함) 서브넷 마스크를 씌우지 않고 그대로 통과
                if (ipStr.find(L':') != std::wstring::npos) {
                    return ipStr;
                }

                size_t slashPos = ipStr.find(L'/');
                std::wstring ip = ipStr.substr(0, slashPos);
                std::wstring suffix = (slashPos != std::wstring::npos) ? ipStr.substr(slashPos + 1) : L"";

                std::wstring newSuffix;

                // 1. '/'가 없는 단일 IP인 경우 -> 기본값 /32 적용
                if (suffix.empty()) {
                    newSuffix = L"32";
                }
                // 2. 뒤에 '.'이 포함된 경우 -> 서브넷 마스크이므로 CIDR로 변환
                else if (suffix.find(L'.') != std::wstring::npos) {
                    int cidr = SubnetMaskToCidr(suffix);
                    // 잘못된 서브넷 마스크 문자열일 경우 32로 fallback
                    newSuffix = std::to_wstring(cidr != -1 ? cidr : 32);
                }
                // 3. 이미 CIDR 형태인 경우 -> 그대로 사용
                else {
                    newSuffix = suffix;
                }

                if (newSuffix == L"32") {
                    return ip; // /32는 생략 가능
                }
                return ip + L"/" + newSuffix;
            }

            /**
             * @brief [공통 헬퍼 함수] 쉼표를 기준으로 IP를 나누고 앞뒤 공백을 제거한 vector 리턴 (CIDR 정규화)
             * @param ipsStr IP 주소 문자열 (예: "192.168.0.0/24, 192.168.0.0/255.255.255.0")
             * @return IP 주소 벡터 (예: { "192.168.0.0/24", "192.168.0.0/255.255.255.0" })
             */
            inline std::vector<std::wstring> SplitIps(const std::wstring& ipsStr) {
                std::vector<std::wstring> tokens;
                size_t start = 0;

                while (start < ipsStr.length()) {
                    // 1. 다음 콤마 위치 찾기
                    size_t end = ipsStr.find(L',', start);
                    if (end == std::wstring::npos) {
                        end = ipsStr.length(); // 콤마가 더 없으면 문자열의 끝을 지정
                    }

                    // 2. 현재 토큰 구간(start ~ end) 안에서 공백이 아닌 첫 문자와 마지막 문자 위치 찾기
                    size_t first = ipsStr.find_first_not_of(L" \t\n\r", start);

                    // 3. 유효한 문자가 존재하고, 그 위치가 콤마(end) 이전인 경우에만 추가
                    if (first != std::wstring::npos && first < end) {
                        size_t last = ipsStr.find_last_not_of(L" \t\n\r", end - 1);

                        // 찾은 범위만큼만 정확히 잘라서 한 번만 할당(push_back)
                        tokens.push_back(NormalizeToCidrFormat(ipsStr.substr(first, last - first + 1)));
                    }

                    // 4. 다음 토큰 검색을 위해 start 인덱스를 콤마 다음으로 이동
                    start = end + 1;
                }

                return tokens;
            }

            /**
             * @brief [공통 헬퍼 함수] 벡터의 IP들을 다시 콤마로 연결
             * @param tokens IP 주소 벡터 (예: { "192.168.0.0/24", "192.168.0.0/255.255.255.0" })
             * @return IP 주소 문자열 (예: 192.168.0.0/24,192.168.0.0/255.255.255.0)
             */
            inline std::wstring JoinIps(const std::vector<std::wstring>& tokens) {
                if (tokens.empty()) return L"";

                // 1. 필요한 총 문자열 길이 사전 계산 및 메모리 예약 (재할당 방지)
                size_t totalLength = 0;
                for (const auto& token : tokens) {
                    totalLength += token.length() + 1; // IP 길이 + 콤마(1)
                }

                std::wstring result;
                result.reserve(totalLength); // 메모리 한 번에 할당

                // 2. 루프 내 불필요한 if문 제거를 위해 첫 번째 원소 미리 삽입
                result += tokens[0];

                // 3. 두 번째 원소부터 콤마와 함께 이어 붙이기
                for (size_t i = 1; i < tokens.size(); ++i) {
                    result += L",";
                    result += tokens[i];
                }

                return result;
            }

            /**
             * @brief [공통 헬퍼 함수] IPv4 문자열을 32비트 정수로 변환
             * @param ipStr IP 주소 문자열 (예: 192.168.1.1)
             * @param outIp 변환된 32비트 정수를 저장할 참조 변수 (예: 0xC0A80101)
             * @return 변환 성공 여부 (유효한 IPv4 문자열이면 true, 아니면 false)
             */
            inline bool ParseIpv4Address(const std::wstring& ipStr, unsigned long& outIp) {
                int a, b, c, d;
                wchar_t dummy; // 쓰레기(Garbage) 문자 감지용 변수

                // %c를 추가하여 4개의 숫자 뒤에 다른 문자가 더 있는지 확인합니다.
                // swscanf_s에서 %c를 사용할 때는 마지막에 버퍼 크기(1)를 반드시 명시해야 합니다.
                int parsedCount = swscanf_s(ipStr.c_str(), L"%d.%d.%d.%d%c", &a, &b, &c, &d, &dummy, 1);

                // 반환값이 정확히 '4'여야만 뒤에 찌꺼기 문자가 없는 완벽한 IP 문자열입니다.
                if (parsedCount == 4) {
                    if (a >= 0 && a <= 255 && b >= 0 && b <= 255 && c >= 0 && c <= 255 && d >= 0 && d <= 255) {
                        outIp = ((unsigned long)a << 24) |
                                ((unsigned long)b << 16) |
                                ((unsigned long)c << 8) |
                                (unsigned long)d;
                        return true;
                    }
                }

                return false;
            }

            /**
             * @brief [공통 헬퍼 함수] ip 또는 subnet이 제공된 IP와 일치하거나 해당 서브넷 대역에 포함되는지 비트 연산 검사
             * @param target 체크할 IP 주소 문자열 (예: 192.168.1.1 or 192.168.1.0/24)
             * @param subnet target이 포함될지 확인할 IP 주소 문자열 (예: 192.168.1.1 or 192.168.1.0/24)
             * @return target이 subnet과 같거나 해당 서브넷 대역에 포함되면 true, 아니면 false
             */
            inline bool IsIpInSubnet(const std::wstring& target, const std::wstring& subnet) {
                // 1. 모든 입력을 "IP/CIDR" 포맷으로 정규화 (예: "1.2.3.4" -> "1.2.3.4/32")
                std::wstring normTarget = NormalizeToCidrFormat(target);
                std::wstring normSubnet = NormalizeToCidrFormat(subnet);

                unsigned long targetIp = 0, subnetIp = 0;
                int targetCidr = 0, subnetCidr = 0;

                // 내부 파싱용 람다(Lambda) 함수: "IP/CIDR" 문자열을 32비트 정수와 CIDR 값으로 분리
                auto parseNormalized = [](const std::wstring& str, unsigned long& outIp, int& outCidr) -> bool {
                    size_t slashPos = str.find(L'/');
                    if (slashPos == std::wstring::npos) {
                        outCidr = 32; // CIDR이 없으면 기본값 32로
                        return ParseIpv4Address(str, outIp);
                    }

                    std::wstring ipPart = str.substr(0, slashPos);
                    std::wstring cidrPart = str.substr(slashPos + 1);

                    // 앞서 만든 엄격한 IPv4 파싱 함수 사용
                    if (!ParseIpv4Address(ipPart, outIp)) return false;
                    if (swscanf_s(cidrPart.c_str(), L"%d", &outCidr) != 1) return false;

                    return true;
                };

                // 2. 문자열 파싱 및 유효성 검사 (실패 시 포함되지 않은 것으로 간주)
                if (!parseNormalized(normTarget, targetIp, targetCidr)) return false;
                if (!parseNormalized(normSubnet, subnetIp, subnetCidr)) return false;

                // 3. 포함 관계 성립 조건 1: 타겟의 대역이 서브넷보다 크면 포함될 수 없음
                // (예: 타겟이 /24 인데, 검사할 서브넷이 /25 라면 다 들어갈 수 없으므로 false)
                if (targetCidr < subnetCidr) {
                    return false;
                }

                // 4. 서브넷 마스크 비트 생성 (0 입력 시 발생하는 UB 방지)
                unsigned long subnetMask = (subnetCidr == 0) ? 0 : (0xFFFFFFFFUL << (32 - subnetCidr));

                // 5. 포함 관계 성립 조건 2: 마스크를 씌운 네트워크 영역이 정확히 일치하는지 비교
                return (targetIp & subnetMask) == (subnetIp & subnetMask);
            }

            /**
             * @brief [공통 헬퍼 함수] 원본 IP 목록(source)에서 타겟(targets) 대역에 포함되는 IP만 필터링하여 반환
             * @param sourceList 필터링할 원본 IP 목록 (예: 차단된 IP 목록, 화이트리스트 목록 등)
             * @param targets 검색할 타겟 IP 또는 서브넷 대역 목록
             * @return targets 대역에 포함되는 sourceList 내의 IP 목록
             */
            inline std::vector<std::wstring> FilterMatchingIps(const std::vector<std::wstring>& sourceList, const std::vector<std::wstring>& targets) {
                std::vector<std::wstring> matchedIps;
                if (sourceList.empty() || targets.empty()) return matchedIps;

                for (const auto& ip : sourceList) {
                    for (const auto& target : targets) {
                        // 원본 IP가 타겟 대역 중 하나라도 속해 있다면 매칭 성공
                        if (IsIpInSubnet(ip, target)) {
                            matchedIps.push_back(ip);
                            break; // 중복 삽입 방지를 위해 다음 원본 IP로 넘어감
                        }
                    }
                }
                return matchedIps;
            }
        }
    }
}
