#pragma once

#include <string>
#include <vector>
#include <array>
#include <cstdint>



namespace Ransom0 {
    namespace Firewall {
        namespace Utils {
            /**
             * @brief IPv4 주소를 문자열로 변환하는 함수
             * @param ip 변환할 32비트 정수 IPv4 주소
             * @param outStr 변환된 문자열 (예: "192.168.1.1")
             * @return true: 성공, false: 실패
             */
            bool Ipv4ToString(uint32_t ip, std::string& outStr);

            /**
             * @brief IPv6 주소를 문자열로 변환하는 함수
             * @param ip 변환할 16바이트 배열 IPv6 주소
             * @param outStr 변환된 문자열 (예: "2001:4860:4860::8888")
             * @return true: 성공, false: 실패
             */
            bool Ipv6ToString(const std::array<uint8_t, 16>& ip, std::string& outStr);

            /**
             * @brief IPv4 주소 문자열을 32비트 정수로 변환하는 함수
             * @param ipStr 변환할 IPv4 주소 문자열 (예: "192.168.1.1")
             * @param outIp 변환된 32비트 정수
             * @return true: 성공, false: 실패
             */
            bool ParseIpv4(const std::string& ipStr, uint32_t& outIp);

            /**
             * @brief IPv6 주소 문자열을 16바이트 배열로 변환하는 함수
             * @param ipStr 변환할 IPv6 주소 문자열 (예: "2001:4860:4860::8888")
             * @param outIp 변환된 16바이트 배열
             * @return true: 성공, false: 실패
             */
            bool ParseIpv6(const std::string& ipStr, std::array<uint8_t, 16>& outIp);

            /**
             * @brief 도메인 이름을 IPv4 및 IPv6 주소 목록으로 한 번에 변환하는 함수
             * @param domain 변환할 도메인 이름 (예: "example.com")
             * @param outIpv4s 변환된 IPv4 주소 벡터
             * @param outIpv6s 변환된 IPv6 주소 벡터
             * @return true: 하나 이상의 IP 해석 성공, false: 실패
             */
            bool ResolveDomainToIps(
                const std::string& domain,
                std::vector<uint32_t>& outIpv4s,
                std::vector<std::array<uint8_t, 16>>& outIpv6s
            );
        }
    }
}
