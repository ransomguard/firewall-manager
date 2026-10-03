#pragma once        // 중복 정의 에러 차단

// #include <windows.h>      // Windows API 기본 헤더
#include <netfw.h>        // Windows Defender 방화벽 인터페이스
#include <string>         // std::wstring
#include <vector>         // std::vector
#include <algorithm>      // std::find
#include <comdef.h>       // _bstr_t 래퍼 클래스
#include "Utils.h"        // 공통 IP 정규화 및 헬퍼 함수

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

namespace Ransom0 {
    namespace Firewall {
        namespace Core {
            class Block {
            private:
                // 내부 전역 상수 (IN / OUT 분리)
                static constexpr const wchar_t* const FIXED_RULE_NAME_IN = L"Block_Malicious_IP_List_IN";
                static constexpr const wchar_t* const FIXED_RULE_NAME_OUT = L"Block_Malicious_IP_List_OUT";
                static constexpr const wchar_t* const FIXED_RULE_DESC_IN = L"Ransom0 엔진에서 관리하는 다중 악성 IP 인바운드 차단 목록입니다.";
                static constexpr const wchar_t* const FIXED_RULE_DESC_OUT = L"Ransom0 엔진에서 관리하는 다중 악성 IP 아웃바운드 차단 목록입니다.";

                /**
                 * @brief [내부 헬퍼 함수] 핵심 엔진: 단방향 룰 동기화 헬퍼. 룰이 존재하지 않으면 새로 생성하고, 해당 룰에 IP 목록을 적용
                 * @param pFwRules 이미 획득한 방화벽 제어 리모컨
                 * @param ruleName 방화벽 룰 이름 (예: FIXED_RULE_NAME_IN)
                 * @param desc 방화벽 룰 설명 (예: FIXED_RULE_DESC_IN)
                 * @param dir 방화벽 룰 방향 (NET_FW_RULE_DIR_IN)
                 * @param ips 적용할 IP 목록 (콤마로 구분된 문자열, 예: "192.168.0.1, 192.168.0.2, 192.168.0.0/24")
                 */
                static inline void Sync(INetFwRules* pFwRules, const wchar_t* ruleName, const wchar_t* desc, NET_FW_RULE_DIRECTION dir, const std::wstring& ips) {
                    // 1. [핵심 방어] 적용할 IP 목록이 비어있다면, 차단할 대상이 없으므로 방화벽 룰 자체를 삭제
                    if (ips.empty()) {
                        // 기존에 룰이 있었다면 삭제하고, 없었다면 무시됨 (안전함)
                        pFwRules->Remove(_bstr_t(ruleName));
                        return;
                    }

                    INetFwRule* pRule = nullptr;
                    HRESULT hr = pFwRules->Item(_bstr_t(ruleName), &pRule);

                    if (SUCCEEDED(hr) && pRule != nullptr) {
                        // 2. 기존 룰이 존재하는 경우
                        pRule->put_RemoteAddresses(_bstr_t(ips.c_str()));

                        // 사용자가 임의로 방화벽 룰을 '사용 안 함'으로 바꿨을 수 있으므로 강제로 다시 켬
                        pRule->put_Enabled(VARIANT_TRUE);

                        pRule->Release();
                    }
                    else {
                        // 3. 기존 룰이 없는 경우 새로 생성
                        hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pRule);
                        if (SUCCEEDED(hr) && pRule != nullptr) {
                            pRule->put_Name(_bstr_t(ruleName));
                            pRule->put_Description(_bstr_t(desc));
                            pRule->put_Action(NET_FW_ACTION_BLOCK);
                            pRule->put_Direction(dir);

                            // ★ 중요: IP 세팅이 "성공(SUCCEEDED)" 했을 때만 Add() 하도록 2차 방어선 구축
                            hr = pRule->put_RemoteAddresses(_bstr_t(ips.c_str()));

                            if (SUCCEEDED(hr)) {
                                // 룰 생성 실패 시 존재하지 않는 상태이므로 성공했을 때만 방화벽 룰을 강제로 켬
                                pRule->put_Enabled(VARIANT_TRUE);
                                pFwRules->Add(pRule);
                            }

                            pRule->Release();
                        }
                    }
                }

                /**
                 * @note 인바운드/아웃바운드 룰에 적용되는 IP는 항상 같아야 하므로, Commit()에서 한 번에 동기화 처리
                 * @brief [내부 헬퍼 함수] 인바운드/아웃바운드 룰을 동시에 업데이트하는 메인 컨트롤 함수
                 * @param pFwRules 이미 획득한 방화벽 제어 리모컨
                 * @param ips 적용할 IP 목록 (콤마로 구분된 문자열, 예: "192.168.0.1, 192.168.0.2, 192.168.0.0/24")
                 */
                static inline void Commit(INetFwRules* pFwRules, const std::vector<std::wstring>& ips) {
                    // 파라미터로 리모컨을 넘겨주며 고속으로 여러 룰을 일괄 업데이트
                    std::wstring finalIps = Ransom0::Firewall::Utils::JoinIps(ips);
                    Sync(pFwRules, FIXED_RULE_NAME_IN, FIXED_RULE_DESC_IN, NET_FW_RULE_DIR_IN, finalIps);
                    Sync(pFwRules, FIXED_RULE_NAME_OUT, FIXED_RULE_DESC_OUT, NET_FW_RULE_DIR_OUT, finalIps);
                }

            public:
                /**
                 * @brief [내부 헬퍼 함수] 방화벽 리모컨(INetFwRules) 획득
                 * @return INetFwRules 포인터 (성공 시 유효한 포인터, 실패 시 nullptr)
                 */
                static inline INetFwRules* GetRules() {
                    INetFwPolicy2* pNetFwPolicy2 = nullptr;
                    INetFwRules* pFwRules = nullptr;

                    if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2))) {
                        pNetFwPolicy2->get_Rules(&pFwRules);
                        pNetFwPolicy2->Release();
                    }
                    return pFwRules;
                }



                // --- [API 함수들] ---

                /**
                 * @brief [list] 등록된 차단 IP 리턴 (IP/CIDR 형식으로 정규화)
                 * @param pFwRules 이미 획득한 방화벽 제어 리모컨
                 * @return 등록된 차단 IP 목록 (예: { "192.168.0.1", "192.168.0.2", "192.168.0.0/24" })
                 */
                static inline std::vector<std::wstring> GetIps(INetFwRules* pFwRules) {
                    std::vector<std::wstring> ipList;
                    if (pFwRules == nullptr) return ipList;

                    INetFwRule* pFwRule = nullptr;

                    // 마스터 룰(IN 룰)만 읽어오기
                    HRESULT hr = pFwRules->Item(_bstr_t(FIXED_RULE_NAME_IN), &pFwRule);

                    if (SUCCEEDED(hr) && pFwRule != nullptr) {
                        BSTR bstrExistingRemotes = nullptr;

                        if (SUCCEEDED(pFwRule->get_RemoteAddresses(&bstrExistingRemotes)) && bstrExistingRemotes != nullptr) {
                            std::wstring existingIps(bstrExistingRemotes);

                            // [칭찬 포인트] BSTR 메모리 해제(SysFreeString)를 아주 정확히 처리하셨습니다!
                            SysFreeString(bstrExistingRemotes);

                            if (existingIps != L"*") {
                                ipList = Ransom0::Firewall::Utils::SplitIps(existingIps);
                            }
                        }
                        pFwRule->Release();
                    }

                    return ipList;
                }

                /**
                 * @brief [clear] 차단 규칙 전체 삭제 (이미 삭제되었거나 없어도 성공 처리)
                 * @param pFwRules 이미 획득한 방화벽 제어 리모컨
                 * @return 성공 시 true (이미 삭제되었거나 없어도 true 반환)
                 */
                static inline bool Clear(INetFwRules* pFwRules) {
                    if (pFwRules == nullptr) return false;

                    // Remove()는 룰이 존재하지 않을 경우 에러(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))를 반환합니다.
                    // 하지만 "이미 없으면 지워진 것과 다름없다"는 논리에 따라 반환값을 의도적으로 무시(Ignore)하여
                    // 예외 없이 부드럽게 넘어가도록(Soft-fail) 처리합니다.
                    pFwRules->Remove(_bstr_t(FIXED_RULE_NAME_IN));
                    pFwRules->Remove(_bstr_t(FIXED_RULE_NAME_OUT));

                    return true;
                }

                /**
                 * @brief [차단 추가] 새 IP를 차단 목록에 병합 및 방화벽 동기화
                 * @param pFwRules 이미 획득한 방화벽 제어 리모컨
                 * @param tokens IP 주소 벡터
                 * @return 정상적으로 수행되어 방화벽 룰이 갱신되었다면 true, 아니면 false
                 */
                static inline bool AddIps(INetFwRules* pFwRules, const std::vector<std::wstring>& tokens) {
                    if (pFwRules == nullptr) return false;

                    if (tokens.empty()) return true;

                    // 2. 현재 방화벽 차단 목록 가져오기
                    std::vector<std::wstring> currentList = GetIps(pFwRules);
                    size_t originalSize = currentList.size();

                    // 3. 새 IP들을 정규화(CIDR)하여 기존 목록 뒤에 합치기
                    for (const auto& ip : tokens) {
                        currentList.push_back(Ransom0::Firewall::Utils::NormalizeToCidrFormat(ip));
                    }

                    // 4. 정렬 및 중복 제거
                    std::sort(currentList.begin(), currentList.end());
                    currentList.erase(std::unique(currentList.begin(), currentList.end()), currentList.end());

                    // 5. 추가된 IP가 없다면 무거운 방화벽 갱신 생략 (Early Return)
                    if (currentList.size() == originalSize) {
                        return true;
                    }

                    // 6. 방화벽 룰 최종 동기화
                    Commit(pFwRules, currentList);

                    return true;
                }

                /**
                 * @brief [차단 해제] 차단 목록에서 특정 IP 제거 및 방화벽 룰 동기화
                 * @param pFwRules 이미 획득한 방화벽 제어 리모컨
                 * @param tokens IP 주소 벡터
                 * @return 정상적으로 수행되어 방화벽 룰이 갱신되었다면 true, 아니면 false
                 */
                static inline bool RemoveIps(INetFwRules* pFwRules, std::vector<std::wstring>& tokens) {
                    if (pFwRules == nullptr) return false;

                    // 1. 삭제할 타겟 IP 문자열 분리 및 정규화
                    if (tokens.empty()) return true;
                    tokens.reserve(tokens.size());

                    // 2. 검색 속도 극대화를 위해 삭제 대상 정렬
                    std::sort(tokens.begin(), tokens.end());

                    // 3. 현재 방화벽 차단 목록 가져오기 (파라미터 주입 버전 호출)
                    std::vector<std::wstring> currentList = GetIps(pFwRules);
                    size_t originalSize = currentList.size();

                    // 4. [핵심] Erase-Remove Idiom과 이분 탐색을 통한 In-place 고속 삭제 (새로운 배열 복사 Zero)
                    currentList.erase(
                        std::remove_if(currentList.begin(), currentList.end(),
                            [&tokens](const std::wstring& ip) {
                                // std::binary_search로 O(log M) 속도로 삭제 대상 확인
                                return std::binary_search(tokens.begin(), tokens.end(), ip);
                            }
                        ),
                        currentList.end()
                    );

                    // 5. [최적화] 지운 게 없다면(크기가 그대로라면) 무거운 방화벽 갱신을 생략하고 얼리 리턴
                    if (currentList.size() == originalSize) {
                        return true;
                    }

                    // 6. IP가 더 이상 없으면 룰 자체를 깔끔하게 파기 (앞서 만든 파라미터 주입 버전 호출)
                    if (currentList.empty()) {
                        return Clear(pFwRules);
                    }

                    // 7. 남은 IP가 있다면 방화벽 룰 최종 동기화
                    Commit(pFwRules, currentList);

                    return true;
                }
            };
        }
    }
}
