#pragma once        // 중복 정의 에러 차단

#include <string>         // std::wstring
#include <vector>         // std::vector

#include "Utils.h"
#include "WhitelistManager.h"
#include "BlockManager.h"

namespace Ransom0 {
    namespace Firewall {
        namespace Block {
            /**
             * @brief [list] 등록된 차단 IP 리턴 (IP/CIDR 형식으로 정규화)
             * @return 등록된 차단 IP 목록 (예: { "192.168.0.1", "192.168.0.2", "192.168.0.0/24" })
             */
            inline std::vector<std::wstring> GetIps() {
                std::vector<std::wstring> ipList;

                // 이미 만들어둔 GetRules()를 재사용하여 코드 중복 제거
                INetFwRules* pRules = Firewall::Core::Block::GetRules();

                if (pRules != nullptr) {
                    ipList = Firewall::Core::Block::GetIps(pRules); // 위에서 만든 파라미터 버전 호출
                    pRules->Release(); // 작업 완료 후 리모컨 반납
                }

                return ipList;
            }

            /**
             * @brief [clear] 차단 규칙 전체 삭제 (이미 삭제되었거나 없어도 성공 처리)
             * @return 성공 시 true (이미 삭제되었거나 없어도 true 반환)
             */
            inline bool Clear() {
                bool success = false;

                // 이미 만들어둔 GetRules()를 재사용하여 COM 초기화 중복을 완벽히 제거
                INetFwRules* pRules = Firewall::Core::Block::GetRules();

                if (pRules != nullptr) {
                    success = Firewall::Core::Block::Clear(pRules);
                    pRules->Release(); // 작업 완료 후 리모컨 반납
                }

                return success;
            }

            /**
             * @brief [차단 추가] 파일 내 저장된 IP 화이트리스트 기반 필터링 후 새 IP를 차단 목록에 병합 및 방화벽 동기화
             * @param ips 추가할 IP 목록 (콤마로 구분된 문자열, 예: "192.168.0.1, 192.168.0.2, 192.168.0.0/24")
             * @return 정상적으로 수행되어 방화벽 룰이 갱신되었다면 true, 아니면 false
             */
            inline bool AddIps(const std::wstring& ips) {
                INetFwRules* pRules = Firewall::Core::Block::GetRules();
                if (!pRules) return false;

                auto whitelist = Firewall::Core::Whitelist::Load();

                // 화이트리스트 대역에 포함된 IP는 차단 룰 적용 제외
                std::vector<std::wstring> newIps = Firewall::Utils::SplitIps(ips);
                std::vector<std::wstring> validNewIps;
                validNewIps.reserve(newIps.size());
                for (const auto& ip : newIps) {
                    if (!Firewall::Core::Whitelist::IsWhitelisted(whitelist, ip)) {
                        validNewIps.push_back(ip);
                    }
                }
                bool result = Firewall::Core::Block::AddIps(pRules, validNewIps);

                pRules->Release();
                return result;
            }

            /**
             * @brief [차단 해제] 차단 목록에서 특정 IP 제거 및 방화벽 룰 동기화
             * @param removeIps 삭제할 대상 IP 문자열 (콤마로 구분된 문자열, 예: "192.168.0.1, 192.168.0.2, 192.168.0.0/24")
             * @return 정상적으로 수행되어 방화벽 룰이 갱신되었다면 true, 아니면 false
             */
            inline bool RemoveIps(const std::wstring& removeIps) {
                // 무거운 COM 리모컨 획득을 딱 한 번만 수행
                INetFwRules* pRules = Firewall::Core::Block::GetRules();
                if (!pRules) return false;

                // 핵심 엔진 호출
                std::vector<std::wstring> tokens = Ransom0::Firewall::Utils::SplitIps(removeIps);
                bool result = Firewall::Core::Block::RemoveIps(pRules, tokens);

                // 리모컨 반납
                pRules->Release();

                return result;
            }
        }

        namespace Whitelist {
            /**
             * @brief [화이트리스트] 파일에서 화이트리스트 IP 목록 읽기 및 자동 정규화
             * @return 화이트리스트 IP 벡터 (정규화된 CIDR 형식)
             */
            inline auto Load() {
                return Firewall::Core::Whitelist::Load();
            }

            /**
             * @brief [화이트리스트] 파일 내 저장된 IP 화이트리스트 전체 초기화(삭제)
             * @return 성공적으로 수행되어 파일에 저장 성공 시 true, 아니면 false
             */
            inline bool Clear() {
                auto list = Load();
                if (Firewall::Core::Whitelist::Clear(list)) {
                    return Firewall::Core::Whitelist::Save(list);
                }
                return true;
            }

            /**
             * @brief [화이트리스트] 파일 내 저장된 IP 화이트리스트에 새 IP 목록 추가 및 차단 목록에서 제거
             * @param ips 콤마로 구분된 추가할 IP 문자열
             * @return 성공적으로 수행되어 파일에 저장 성공 시 true, 아니면 false
             */
            inline bool AddIps(const std::wstring& ips) {
                if (ips.empty()) return true;

                auto list = Load();
                std::vector<std::wstring> newIps = Firewall::Utils::SplitIps(ips);
                if (Firewall::Core::Whitelist::AddIps(list, newIps)) {
                    bool success = Firewall::Core::Whitelist::Save(list);
                    if (success) {
                        // 화이트리스트에 새 IP 또는 범위가 추가되었으므로, 차단 목록에서 해당하는 IP 제거
                        auto rules = Firewall::Core::Block::GetRules();
                        auto blockedIps = Firewall::Core::Block::GetIps(rules);
                        auto removeIps = Firewall::Utils::FilterMatchingIps(blockedIps, list);
                        Firewall::Core::Block::RemoveIps(rules, removeIps);
                    }
                    return success;
                }
                return true;
            }

            /**
             * @brief [화이트리스트] 파일 내 저장된 IP 화이트리스트에서 특정 IP 목록 제거
             * @param removeIps 콤마로 구분된 삭제할 IP 문자열
             * @return 성공적으로 수행되어 파일에 저장 성공 시 true, 아니면 false
             */
            inline bool RemoveIps(const std::wstring& ips) {
                if (ips.empty()) return true;

                auto list = Load();
                std::vector<std::wstring> removeIps = Firewall::Utils::SplitIps(ips);
                if (Firewall::Core::Whitelist::RemoveIps(list, removeIps)) {
                    return Firewall::Core::Whitelist::Save(list);
                }
                return true;
            }

            /**
             * @brief [화이트리스트] 파일 내 저장된 IP 화이트리스트에서 특정 IP 또는 서브넷 대역이 화이트리스트에 존재하는지 검사
             * @param ip 체크할 IP 주소 문자열 (예: 192.168.0.1 or 192.168.0.0/24)
             * @return whitelist에 ip가 존재하거나, ip가 whitelist의 서브넷 대역에 포함되면 true, 아니면 false
             */
            inline bool IsWhitelisted(const std::wstring& ip) {
                auto list = Load();
                return Firewall::Core::Whitelist::IsWhitelisted(list, ip);
            }
        }
    }
}
