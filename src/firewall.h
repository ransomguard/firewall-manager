#pragma once

#include <string>
#include <vector>
#include <memory>



namespace Ransom0 {
    namespace Firewall {
        struct WhitelistRecord {
            std::string type;  // "ipv4", "ipv6", "domain"
            std::string value; // 원본 입력 (예: "google.com")
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
             * @brief 방화벽 격리 활성화 (Block All + DNS 허용)
             * @return 성공 시 true, 실패 시(방화벽이 이미 활성화된 경우) false
             */
            bool Enable();

            /**
             * @brief 화이트리스트 설정
             * @param whitelistTargets 화이트리스트 대상 IP/도메인 문자열 벡터
             * @return 성공 시 true, 실패 시(방화벽이 활성화되어 있지 않은 경우) false
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
