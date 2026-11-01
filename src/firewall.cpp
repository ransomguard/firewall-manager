#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <cstring>

#include "firewall.h"
#include "utils.h"

#pragma comment(lib, "Fwpuclnt.lib")



namespace {
    // 공통 WFP 필터 등록 헬퍼
    void AddFilter(HANDLE engineHandle, const GUID& layerKey, FWP_ACTION_TYPE actionType, const wchar_t* name,
                   FWPM_FILTER_CONDITION0* conditions = nullptr, UINT32 numConditions = 0,
                   std::vector<UINT64>* outFilterIds = nullptr) {
        FWPM_FILTER0 filter = { 0 };
        filter.layerKey = layerKey;
        filter.action.type = actionType;
        filter.weight.type = FWP_EMPTY;
        filter.numFilterConditions = numConditions;
        filter.filterCondition = conditions;
        filter.displayData.name = const_cast<wchar_t*>(name);

        UINT64 filterId = 0;
        if (FwpmFilterAdd0(engineHandle, &filter, NULL, &filterId) == ERROR_SUCCESS) {
            if (outFilterIds) {
                outFilterIds->push_back(filterId);
            }
        }
    }

    // 포트 조건 설정 헬퍼
    void SetPortCondition(FWPM_FILTER_CONDITION0& cond, uint16_t port) {
        cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        cond.matchType = FWP_MATCH_EQUAL;
        cond.conditionValue.type = FWP_UINT16;
        cond.conditionValue.uint16 = port;
    }

    // IPv4 단일 IP 허용 필터 등록
    void AddIpv4Filter(HANDLE engineHandle, uint32_t ip, uint16_t port, std::vector<UINT64>& filterIds) {
        FWPM_FILTER_CONDITION0 cond[2] = { 0 };
        cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond[0].matchType = FWP_MATCH_EQUAL;
        cond[0].conditionValue.type = FWP_UINT32;
        cond[0].conditionValue.uint32 = ip;

        UINT32 numConds = 1;
        if (port != 0) {
            SetPortCondition(cond[1], port);
            numConds = 2;
        }

        AddFilter(engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, L"Ransom0_Whitelist_V4", cond, numConds, &filterIds);
    }

    // IPv4 CIDR 대역 허용 필터 등록
    void AddIpv4CidrFilter(HANDLE engineHandle, uint32_t ip, uint32_t mask, uint16_t port, std::vector<UINT64>& filterIds) {
        FWP_V4_ADDR_AND_MASK v4Mask = { 0 };
        v4Mask.addr = ip;
        v4Mask.mask = mask;

        FWPM_FILTER_CONDITION0 cond[2] = { 0 };
        cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond[0].matchType = FWP_MATCH_EQUAL;
        cond[0].conditionValue.type = FWP_V4_ADDR_MASK;
        cond[0].conditionValue.v4AddrMask = &v4Mask;

        UINT32 numConds = 1;
        if (port != 0) {
            SetPortCondition(cond[1], port);
            numConds = 2;
        }

        AddFilter(engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, L"Ransom0_Whitelist_V4_CIDR", cond, numConds, &filterIds);
    }

    // IPv6 단일 IP 허용 필터 등록
    void AddIpv6Filter(HANDLE engineHandle, const std::array<uint8_t, 16>& ip, uint16_t port, std::vector<UINT64>& filterIds) {
        FWP_BYTE_ARRAY16 v6Addr = { 0 };
        std::memcpy(v6Addr.byteArray16, ip.data(), 16);

        FWPM_FILTER_CONDITION0 cond[2] = { 0 };
        cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond[0].matchType = FWP_MATCH_EQUAL;
        cond[0].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
        cond[0].conditionValue.byteArray16 = &v6Addr;

        UINT32 numConds = 1;
        if (port != 0) {
            SetPortCondition(cond[1], port);
            numConds = 2;
        }

        AddFilter(engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_PERMIT, L"Ransom0_Whitelist_V6", cond, numConds, &filterIds);
    }

    // IPv6 CIDR 대역 허용 필터 등록
    void AddIpv6CidrFilter(HANDLE engineHandle, const std::array<uint8_t, 16>& ip, uint8_t prefix, uint16_t port, std::vector<UINT64>& filterIds) {
        FWP_V6_ADDR_AND_MASK v6Mask = { 0 };
        std::memcpy(v6Mask.addr, ip.data(), 16);
        v6Mask.prefixLength = prefix;

        FWPM_FILTER_CONDITION0 cond[2] = { 0 };
        cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        cond[0].matchType = FWP_MATCH_EQUAL;
        cond[0].conditionValue.type = FWP_V6_ADDR_MASK;
        cond[0].conditionValue.v6AddrMask = &v6Mask;

        UINT32 numConds = 1;
        if (port != 0) {
            SetPortCondition(cond[1], port);
            numConds = 2;
        }

        AddFilter(engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_PERMIT, L"Ransom0_Whitelist_V6_CIDR", cond, numConds, &filterIds);
    }

    // 전체 IP 대상 단독 포트 허용 필터 등록 (V4 및 V6 모두 허용)
    void AddPortFilter(HANDLE engineHandle, uint16_t port, std::vector<UINT64>& filterIds) {
        FWPM_FILTER_CONDITION0 cond = { 0 };
        SetPortCondition(cond, port);

        AddFilter(engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, L"Ransom0_Whitelist_Port_V4", &cond, 1, &filterIds);
        AddFilter(engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_PERMIT, L"Ransom0_Whitelist_Port_V6", &cond, 1, &filterIds);
    }

    // 단일 IPv4 레코드 및 필터 처리 헬퍼
    void ProcessIpv4Target(HANDLE engineHandle, uint32_t ip, uint16_t port,
                           Ransom0::Firewall::WhitelistRecord& record, bool isActive,
                           std::vector<UINT64>& filterIds) {
        std::string strIp;
        if (Ransom0::Firewall::Utils::Ipv4ToString(ip, strIp)) {
            record.resolvedIpv4.push_back(strIp);
        }
        if (isActive) {
            AddIpv4Filter(engineHandle, ip, port, filterIds);
        }
    }

    // 단일 IPv6 레코드 및 필터 처리 헬퍼
    void ProcessIpv6Target(HANDLE engineHandle, const std::array<uint8_t, 16>& ip, uint16_t port,
                           Ransom0::Firewall::WhitelistRecord& record, bool isActive,
                           std::vector<UINT64>& filterIds) {
        std::string strIp;
        if (Ransom0::Firewall::Utils::Ipv6ToString(ip, strIp)) {
            record.resolvedIpv6.push_back(strIp);
        }
        if (isActive) {
            AddIpv6Filter(engineHandle, ip, port, filterIds);
        }
    }
}



namespace Ransom0 {
    namespace Firewall {
        // 내부 구현체 정의
        struct Manager::Impl {
            HANDLE engineHandle = NULL;
            std::vector<UINT64> whitelistFilterIds;
        };

        Manager::Manager() : pImpl(std::make_unique<Impl>()) {}

        Manager::~Manager() {
            Disable();
        }

        bool Manager::IsActive() const {
            return pImpl->engineHandle != NULL;
        }

        bool Manager::Enable() {
            // 이미 활성화되어 있다면 중복 실행 방지
            if (IsActive()) return false;

            FWPM_SESSION0 session = { 0 };
            session.flags = FWPM_SESSION_FLAG_DYNAMIC; // 프로세스 종료 시 자동 롤백

            // WFP 엔진 핸들 열기
            DWORD result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &pImpl->engineHandle);
            if (result != ERROR_SUCCESS) {
                pImpl->engineHandle = NULL;
                return false;
            }

            // 1. 아웃바운드 전체 차단 필터 (V4 / V6)
            AddFilter(pImpl->engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_BLOCK, L"Ransom0_Block_All_V4");
            AddFilter(pImpl->engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_BLOCK, L"Ransom0_Block_All_V6");

            // 2. DNS 허용 필터 (포트 53 허용)
            FWPM_FILTER_CONDITION0 dnsCond = { 0 };
            SetPortCondition(dnsCond, 53);
            AddFilter(pImpl->engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, L"Ransom0_Allow_DNS_V4", &dnsCond, 1);
            AddFilter(pImpl->engineHandle, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_ACTION_PERMIT, L"Ransom0_Allow_DNS_V6", &dnsCond, 1);

            return true;
        }

        bool Manager::setWhitelist(const std::vector<std::string>& whitelistTargets, std::vector<WhitelistRecord>* outRecords) {
            if (outRecords) outRecords->clear();

            bool isActive = IsActive();

            // 기존에 등록된 화이트리스트 필터 제거
            if (isActive) {
                for (UINT64 filterId : pImpl->whitelistFilterIds) {
                    FwpmFilterDeleteById0(pImpl->engineHandle, filterId);
                }
                pImpl->whitelistFilterIds.clear();
            }

            // 새로운 화이트리스트 목록 등록 및 파싱
            for (const auto& rawTarget : whitelistTargets) {
                std::string hostPart;
                uint16_t port = 0;

                // 잘못된 형식은 스킵
                if (!Utils::SplitHostAndPort(rawTarget, hostPart, port)) continue;

                WhitelistRecord record;
                record.value = rawTarget;
                record.port = port;

                bool isUrl = (rawTarget.find("://") != std::string::npos);

                // 1단계: 단독 포트 지정 검사 (예: "*:8080" 또는 "8080")
                if (hostPart == "*") {
                    record.type = "port";
                    if (isActive && port != 0) {
                        AddPortFilter(pImpl->engineHandle, port, pImpl->whitelistFilterIds);
                    }
                } else {
                    uint32_t singleIpv4 = 0;
                    uint32_t ipv4Mask = 0;
                    std::array<uint8_t, 16> singleIpv6 = { 0 };
                    uint8_t ipv6Prefix = 0;

                    // 2단계: IPv4 CIDR 대역 검사 (예: "192.168.0.0/24")
                    if (Utils::ParseCidrV4(hostPart, singleIpv4, ipv4Mask)) {
                        record.type = "ipv4";
                        record.cidr = Utils::MaskToPrefixV4(ipv4Mask);
                        Utils::Ipv4ToString(singleIpv4, record.ip);
                        if (isActive) {
                            AddIpv4CidrFilter(pImpl->engineHandle, singleIpv4, ipv4Mask, port, pImpl->whitelistFilterIds);
                        }
                    }
                    // 3단계: IPv6 CIDR 대역 검사 (예: "fd00::/64")
                    else if (Utils::ParseCidrV6(hostPart, singleIpv6, ipv6Prefix)) {
                        record.type = "ipv6";
                        record.cidr = ipv6Prefix;
                        Utils::Ipv6ToString(singleIpv6, record.ip);
                        if (isActive) {
                            AddIpv6CidrFilter(pImpl->engineHandle, singleIpv6, ipv6Prefix, port, pImpl->whitelistFilterIds);
                        }
                    }
                    // 4단계: 순수 단일 IPv4 검사 (예: "192.168.1.1")
                    else if (Utils::ParseIpv4(hostPart, singleIpv4)) {
                        if (isUrl) {
                            record.type = "url";
                            record.domain = hostPart;
                            ProcessIpv4Target(pImpl->engineHandle, singleIpv4, port, record, isActive, pImpl->whitelistFilterIds);
                        } else {
                            record.type = "ipv4";
                            record.cidr = 32;
                            Utils::Ipv4ToString(singleIpv4, record.ip);
                            if (isActive) {
                                AddIpv4Filter(pImpl->engineHandle, singleIpv4, port, pImpl->whitelistFilterIds);
                            }
                        }
                    }
                    // 5단계: 순수 단일 IPv6 검사 (예: "fd00::1")
                    else if (Utils::ParseIpv6(hostPart, singleIpv6)) {
                        if (isUrl) {
                            record.type = "url";
                            record.domain = hostPart;
                            ProcessIpv6Target(pImpl->engineHandle, singleIpv6, port, record, isActive, pImpl->whitelistFilterIds);
                        } else {
                            record.type = "ipv6";
                            record.cidr = 128;
                            Utils::Ipv6ToString(singleIpv6, record.ip);
                            if (isActive) {
                                AddIpv6Filter(pImpl->engineHandle, singleIpv6, port, pImpl->whitelistFilterIds);
                            }
                        }
                    }
                    // 6단계: 도메인 또는 URL (IPv4 + IPv6 동시 DNS 해석)
                    else {
                        record.type = isUrl ? "url" : "domain";
                        record.domain = hostPart;

                        std::vector<uint32_t> ipv4List;
                        std::vector<std::array<uint8_t, 16>> ipv6List;

                        Utils::ResolveDomainToIps(hostPart, ipv4List, ipv6List);

                        for (uint32_t ipVal : ipv4List) {
                            ProcessIpv4Target(pImpl->engineHandle, ipVal, port, record, isActive, pImpl->whitelistFilterIds);
                        }
                        for (const auto& ipv6Val : ipv6List) {
                            ProcessIpv6Target(pImpl->engineHandle, ipv6Val, port, record, isActive, pImpl->whitelistFilterIds);
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
