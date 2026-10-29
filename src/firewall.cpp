#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>

#include "firewall.h"
#include "utils.h"

#pragma comment(lib, "Fwpuclnt.lib")



namespace Ransom0 {
    namespace Firewall {
        // 내부 구현체 정의
        struct Manager::Impl {
            HANDLE engineHandle = NULL;
            std::vector<UINT64> whitelistFilterIds;
        };

        Manager::Manager() : pImpl(std::make_unique<Impl>()) {}

        Manager::~Manager() {
            Disable(); // 객체 소멸 시 자동 롤백 보장 (RAII)
        }

        bool Manager::IsActive() const {
            return pImpl->engineHandle != NULL;
        }

        bool Manager::Enable() {
            // 이미 활성화되어 있다면 중복 실행 방지
            if (IsActive()) return false;

            FWPM_SESSION0 session = { 0 };
            session.flags = FWPM_SESSION_FLAG_DYNAMIC; // 핵심: 프로세스 종료 시 자동 100% 롤백

            // WFP 엔진 핸들 열기
            DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &pImpl->engineHandle);
            if (result != ERROR_SUCCESS) return false;

            // ==========================================
            // 1. 방패 (Block All) - 조건 0개 (가장 낮은 우선순위)
            // ==========================================
            // IPv4 아웃바운드 차단
            FWPM_FILTER0 blockFilterV4 = { 0 };
            blockFilterV4.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            blockFilterV4.action.type = FWP_ACTION_BLOCK;
            blockFilterV4.weight.type = FWP_EMPTY; // WFP 자동 가중치 사용
            blockFilterV4.displayData.name = (wchar_t*)L"Ransom0_BlockAll_V4";
            FwpmFilterAdd0(pImpl->engineHandle, &blockFilterV4, NULL, NULL);

            // IPv6 아웃바운드 차단
            FWPM_FILTER0 blockFilterV6 = { 0 };
            blockFilterV6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            blockFilterV6.action.type = FWP_ACTION_BLOCK;
            blockFilterV6.weight.type = FWP_EMPTY; // WFP 자동 가중치 사용
            blockFilterV6.displayData.name = (wchar_t*)L"Ransom0_BlockAll_V6";
            FwpmFilterAdd0(pImpl->engineHandle, &blockFilterV6, NULL, NULL);

            // ==========================================
            // 2. DNS 허용 (UDP 53) - 조건 2개 (가장 높은 우선순위)
            // ==========================================
            FWPM_FILTER_CONDITION0 dnsCond[2] = { 0 };
            // 프로토콜 = UDP
            dnsCond[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            dnsCond[0].matchType = FWP_MATCH_EQUAL;
            dnsCond[0].conditionValue.type = FWP_UINT8;
            dnsCond[0].conditionValue.uint8 = IPPROTO_UDP;
            // 원격 포트 = 53
            dnsCond[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            dnsCond[1].matchType = FWP_MATCH_EQUAL;
            dnsCond[1].conditionValue.type = FWP_UINT16;
            dnsCond[1].conditionValue.uint16 = 53;

            // IPv4 DNS 허용
            FWPM_FILTER0 dnsFilterV4 = { 0 };
            dnsFilterV4.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            dnsFilterV4.action.type = FWP_ACTION_PERMIT;
            dnsFilterV4.weight.type = FWP_EMPTY; // WFP 자동 가중치 사용
            dnsFilterV4.numFilterConditions = 2;
            dnsFilterV4.filterCondition = dnsCond;
            dnsFilterV4.displayData.name = (wchar_t*)L"Ransom0_AllowDNS_V4";

            FwpmFilterAdd0(pImpl->engineHandle, &dnsFilterV4, NULL, NULL);

            // IPv6 DNS 허용
            FWPM_FILTER0 dnsFilterV6 = { 0 };
            dnsFilterV6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            dnsFilterV6.action.type = FWP_ACTION_PERMIT;
            dnsFilterV6.weight.type = FWP_EMPTY; // WFP 자동 가중치 사용
            dnsFilterV6.numFilterConditions = 2;
            dnsFilterV6.filterCondition = dnsCond;
            dnsFilterV6.displayData.name = (wchar_t*)L"Ransom0_AllowDNS_V6";

            FwpmFilterAdd0(pImpl->engineHandle, &dnsFilterV6, NULL, NULL);

            return true;
        }

        bool Manager::setWhitelist(const std::vector<std::string>& whitelistTargets, std::vector<WhitelistRecord>* outRecords) {
            const bool isActive = IsActive();
            
            // 방화벽이 켜져 있을 때만 기존 화이트리스트 필터 제거
            if (isActive) {
                for (UINT64 filterId : pImpl->whitelistFilterIds) {
                    FwpmFilterDeleteById0(pImpl->engineHandle, filterId);
                }
                pImpl->whitelistFilterIds.clear();
            }

            // 출력용 레코드 벡터 초기화
            if (outRecords) outRecords->clear();

            // 입력값을 순회하며 IPv4 / IPv6 / 도메인 해석
            for (const auto& targetStr : whitelistTargets) {

                // 출력용 레코드 초기화
                WhitelistRecord record;
                if (outRecords) record.value = targetStr;

                std::vector<uint32_t> ipv4List;
                std::vector<std::array<uint8_t, 16>> ipv6List;
                uint32_t singleIpv4 = 0;
                std::array<uint8_t, 16> singleIpv6 = { 0 };

                // 1단계: 입력값이 순수 IPv4 문자열인지 검사
                if (Utils::ParseIpv4(targetStr, singleIpv4)) {
                    if (outRecords) record.type = "ipv4";
                    ipv4List.push_back(singleIpv4);
                }
                // 2단계: 입력값이 순수 IPv6 문자열인지 검사
                else if (Utils::ParseIpv6(targetStr, singleIpv6)) {
                    if (outRecords) record.type = "ipv6";
                    ipv6List.push_back(singleIpv6);
                }
                // 3단계: IP가 아니라면 도메인으로 간주하고 DNS 해석 (IPv4 + IPv6 모두 조회)
                else {
                    if (outRecords) record.type = "domain";
                    Utils::ResolveDomainToIps(targetStr, ipv4List, ipv6List);
                }

                // 찾아낸 모든 IPv4에 대해 처리
                for (uint32_t ipVal : ipv4List) {
                    // 출력용 레코드에 해석된 IP 추가
                    if (outRecords) {
                        std::string strIp;
                        if (Utils::Ipv4ToString(ipVal, strIp)) record.resolvedIpv4.push_back(strIp);
                    }

                    // 방화벽이 켜져 있을 때만 실제 WFP 커널 룰(바늘) 추가
                    if (isActive) {
                        FWPM_FILTER_CONDITION0 allowCond = { 0 };
                        allowCond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                        allowCond.matchType = FWP_MATCH_EQUAL;
                        allowCond.conditionValue.type = FWP_UINT32;
                        allowCond.conditionValue.uint32 = ipVal;

                        FWPM_FILTER0 allowFilter = { 0 };
                        allowFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                        allowFilter.action.type = FWP_ACTION_PERMIT;
                        allowFilter.weight.type = FWP_EMPTY; // WFP 자동 가중치 사용
                        allowFilter.numFilterConditions = 1;
                        allowFilter.filterCondition = &allowCond;
                        allowFilter.displayData.name = (wchar_t*)L"Ransom0_Whitelist_V4";

                        UINT64 filterId = 0;
                        if (FwpmFilterAdd0(pImpl->engineHandle, &allowFilter, NULL, &filterId) == ERROR_SUCCESS) {
                            pImpl->whitelistFilterIds.push_back(filterId);
                        }
                    }
                }

                // 찾아낸 모든 IPv6에 대해 처리
                for (const auto& ipv6Val : ipv6List) {
                    // 출력용 레코드에 해석된 IP 추가
                    if (outRecords) {
                        std::string strIp;
                        if (Utils::Ipv6ToString(ipv6Val, strIp)) record.resolvedIpv6.push_back(strIp);
                    }

                    // 방화벽이 켜져 있을 때만 실제 WFP 커널 룰(바늘) 추가
                    if (isActive) {
                        FWP_BYTE_ARRAY16 byteArray16 = { 0 };
                        std::memcpy(byteArray16.byteArray16, ipv6Val.data(), 16);

                        FWPM_FILTER_CONDITION0 allowCond = { 0 };
                        allowCond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                        allowCond.matchType = FWP_MATCH_EQUAL;
                        allowCond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
                        allowCond.conditionValue.byteArray16 = &byteArray16;

                        FWPM_FILTER0 allowFilter = { 0 };
                        allowFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                        allowFilter.action.type = FWP_ACTION_PERMIT;
                        allowFilter.weight.type = FWP_EMPTY; // WFP 자동 가중치 사용
                        allowFilter.numFilterConditions = 1;
                        allowFilter.filterCondition = &allowCond;
                        allowFilter.displayData.name = (wchar_t*)L"Ransom0_Whitelist_V6";

                        UINT64 filterId = 0;
                        if (FwpmFilterAdd0(pImpl->engineHandle, &allowFilter, NULL, &filterId) == ERROR_SUCCESS) {
                            pImpl->whitelistFilterIds.push_back(filterId);
                        }
                    }
                }

                // 완료된 레코드를 출력 배열에 추가
                if (outRecords) {
                    outRecords->push_back(record);
                }
            }

            return true;
        }

        void Manager::Disable() {
            if (pImpl->engineHandle != NULL) {
                // 핸들을 닫는 순간, 등록했던 모든 필터(방패, 바늘)가 OS에 의해 100% 삭제 및 롤백됨
                FwpmEngineClose0(pImpl->engineHandle);
                pImpl->engineHandle = NULL;
                pImpl->whitelistFilterIds.clear();
            }
        }
    }
}
