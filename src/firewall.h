#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>



namespace Ransom0 {
    namespace Firewall {
        enum class Direction : uint8_t {
            Outbound = 1 << 0,
            Inbound  = 1 << 1,
            Both     = Outbound | Inbound
        };

        std::string DirectionToString(Direction dir);
        bool ParseDirection(const std::string& str, Direction& outDir);

        struct WhitelistRecord {
            std::string type;   // "ipv4", "ipv6", "domain", "url", "port"
            std::string value;  // 원본 입력값

            std::string ip;     // ipv4 또는 ipv6 주소 (정규화된 IP/네트워크 주소)
            std::string domain; // domain 또는 url의 호스트
            uint16_t port = 0;  // 0인 경우 포트 미지정
            uint8_t cidr = 0;   // CIDR prefix (ipv4: 32, ipv6: 128)

            std::vector<std::string> resolvedIpv4;
            std::vector<std::string> resolvedIpv6;
        };

        class Manager {
        public:
            Manager();
            ~Manager();

            // 복사 방지 (엔진 핸들 중복 방지)
            Manager(const Manager&) = delete;
            Manager& operator=(const Manager&) = delete;

            /**
             * @brief 현재 방화벽 격리 활성화 여부 확인
             * @return 활성화되어 있으면 true, 아니면 false
             */
            bool IsActive() const;

            /**
             * @brief 현재 설정된 트래픽 방향 조회
             * @return Direction (Outbound, Inbound, Both)
             */
            Direction GetDirection() const;

            /**
             * @brief 트래픽 방향 설정
             * @param dir 설정할 방향 (Outbound, Inbound, Both)
             */
            void SetDirection(Direction dir);

            /**
             * @brief 방화벽 격리 활성화 (Block All + DNS 허용)
             * @param dir 차단 및 제어할 트래픽 방향 (기본값: Both)
             * @return 성공 시 true, 실패 시(방화벽이 이미 활성화된 경우) false
             */
            bool Enable(Direction dir = Direction::Both);

            /**
             * @brief 화이트리스트 설정
             * @param whitelistTargets 화이트리스트 대상 IP/도메인/CIDR/포트/URL 문자열 벡터
             * @param outRecords 파싱 및 해석된 WhitelistRecord 목록 (선택)
             * @return 성공 시 true
             */
            bool setWhitelist(const std::vector<std::string>& whitelistTargets, std::vector<WhitelistRecord>* outRecords = nullptr);

            /**
             * @brief 방화벽 격리 비활성화 (모든 룰 롤백)
             * @return void
             */
            void Disable();

        private:
            struct Impl; // 실제 구현체를 가리키는 껍데기
            std::unique_ptr<Impl> pImpl;
        };
    }
}
