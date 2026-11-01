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
             * @param ip 변환할 32비트 정수 IPv4 주소 (Host Byte Order)
             * @param outStr 변환된 문자열 (예: "192.168.1.1")
             * @return true: 성공, false: 실패
             */
            bool Ipv4ToString(uint32_t ip, std::string& outStr);

            /**
             * @brief IPv6 주소를 문자열로 변환하는 함수
             * @param ip 변환할 16바이트 배열 IPv6 주소 (Network Byte Order)
             * @param outStr 변환된 문자열 (예: "2001:4860:4860::8888")
             * @return true: 성공, false: 실패
             */
            bool Ipv6ToString(const std::array<uint8_t, 16>& ip, std::string& outStr);

            /**
             * @brief 서브넷 마스크(Host Byte Order)에서 프리픽스 길이(0~32)를 계산하는 함수
             * @param mask 서브넷 마스크
             * @return 프리픽스 길이
             */
            uint8_t MaskToPrefixV4(uint32_t mask);

            /**
             * @brief IPv4 주소 문자열을 32비트 정수로 변환하는 함수
             * @param ipStr 변환할 IPv4 주소 문자열 (예: "192.168.1.1")
             * @param outIp 변환된 32비트 정수 (Host Byte Order)
             * @return true: 성공, false: 실패
             */
            bool ParseIpv4(const std::string& ipStr, uint32_t& outIp);

            /**
             * @brief IPv6 주소 문자열을 16바이트 배열로 변환하는 함수
             * @param ipStr 변환할 IPv6 주소 문자열 (예: "2001:4860:4860::8888")
             * @param outIp 변환된 16바이트 배열 (Network Byte Order)
             * @return true: 성공, false: 실패
             */
            bool ParseIpv6(const std::string& ipStr, std::array<uint8_t, 16>& outIp);

            /**
             * @brief IPv4 CIDR 문자열(예: "192.168.0.0/24")을 IP와 마스크로 변환하는 함수
             * @param cidrStr 변환할 IPv4 CIDR 문자열
             * @param outIp 마스킹된 네트워크 IPv4 주소 (Host Byte Order)
             * @param outMask 서브넷 마스크 (Host Byte Order)
             * @return true: 성공, false: 실패
             */
            bool ParseCidrV4(const std::string& cidrStr, uint32_t& outIp, uint32_t& outMask);

            /**
             * @brief IPv6 CIDR 문자열(예: "fd00::/64" 또는 "fd00::1/64")을 IP와 프리픽스로 변환하는 함수
             * @param cidrStr 변환할 IPv6 CIDR 문자열
             * @param outIp 마스킹된 네트워크 IPv6 주소 (Network Byte Order)
             * @param outPrefix 프리픽스 길이 (0~128)
             * @return true: 성공, false: 실패
             */
            bool ParseCidrV6(const std::string& cidrStr, std::array<uint8_t, 16>& outIp, uint8_t& outPrefix);

            /**
             * @brief URL 문자열에서 Host와 Port를 파싱하는 함수
             * @param url 파싱할 URL (예: "https://example.com:8443/api/v1")
             * @param outHost 추출된 호스트 (도메인 또는 IP 문자열)
             * @param outPort 추출된 포트 (스키마 기본 포트 또는 지정 포트)
             * @return true: URL 형식 파싱 성공, false: URL 아님 또는 파싱 실패
             */
            bool ParseUrl(const std::string& url, std::string& outHost, uint16_t& outPort);

            /**
             * @brief 입력 대상(IP, 도메인, URL, 포트 등)에서 Host 부분과 Port를 분리하는 함수
             * @param input 원본 입력 문자열 (예: "192.168.1.1:8080", "https://example.com/api", "*:443", "10.0.0.0/24:22")
             * @param outHost 분리된 Host 문자열 (단독 포트인 경우 "*")
             * @param outPort 지정된 포트 (생략된 경우 0)
             * @return true: 유효한 형식, false: 실패
             */
            bool SplitHostAndPort(const std::string& input, std::string& outHost, uint16_t& outPort);

            /**
             * @brief 도메인 이름을 IPv4 및 IPv6 주소 목록으로 한 번에 변환하는 함수
             * @param domain 변환할 도메인 이름 (예: "example.com")
             * @param outIpv4s 변환된 IPv4 주소 벡터 (Host Byte Order)
             * @param outIpv6s 변환된 IPv6 주소 벡터 (Network Byte Order)
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
