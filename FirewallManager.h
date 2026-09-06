#pragma once        // 중복 정의 에러 차단

#include <windows.h>      // Windows API 기본 헤더
#include <netfw.h>        // Windows Defender 방화벽 인터페이스
#include <string>         // std::wstring
#include <sstream>        // std::wstringstream
#include <vector>         // std::vector
#include <algorithm>      // std::find
#include <comdef.h>       // _bstr_t 래퍼 클래스

#pragma comment(lib, "ole32.lib")    
#pragma comment(lib, "oleaut32.lib") 

// 내부 전역 상수
const wchar_t* const FIXED_RULE_NAME = L"Block_Malicious_IP_List";
const wchar_t* const FIXED_RULE_DESC = L"자동 관리되는 다중 악성 IP 인바운드 차단 목록입니다.";

// [내부 헬퍼 함수] CIDR 값(예: 24)을 서브넷 마스크(예: 255.255.255.0) 문자열로 변환
inline std::wstring CidrToSubnetMask(int cidr) {
    if (cidr < 0 || cidr > 32) return L"255.255.255.255";
    unsigned long mask = (cidr == 0) ? 0 : (0xFFFFFFFF << (32 - cidr));
    
    std::wstringstream wss;
    wss << ((mask >> 24) & 0xFF) << L"."
        << ((mask >> 16) & 0xFF) << L"."
        << ((mask >> 8) & 0xFF) << L"."
        << (mask & 0xFF);
    return wss.str();
}

// [내부 헬퍼 함수] 사용자 입력 IP를 방화벽 내부 표준 포맷(예: "1.2.3.4/255.255.255.0")으로 강제 변환 (정규화)
inline std::wstring NormalizeIpInput(const std::wstring& ip) {
    // IPv6의 경우 (콜론 포함) 서브넷 마스크를 씌우지 않고 그대로 통과
    if (ip.find(L':') != std::wstring::npos) {
        return ip;
    }

    size_t slashPos = ip.find(L'/');
    if (slashPos == std::wstring::npos) {
        // 1. 단일 IP (예: "1.2.3.4") -> "/255.255.255.255" 추가
        return ip + L"/255.255.255.255";
    } 
    else {
        std::wstring suffix = ip.substr(slashPos + 1);
        // 슬래시 뒤에 점(.)이 없다면 CIDR 표기법(예: /24)으로 간주
        if (suffix.find(L'.') == std::wstring::npos) {
            try {
                int cidr = std::stoi(suffix);
                // 2. CIDR (예: "1.2.3.4/24") -> "/255.255.255.0" 으로 변환
                return ip.substr(0, slashPos) + L"/" + CidrToSubnetMask(cidr);
            } catch (...) {
                return ip; // 숫자 변환 실패 시 원본 리턴
            }
        }
    }
    // 3. 이미 내부 표준 포맷이면 그대로 반환
    return ip;
}

// [내부 헬퍼 함수] 문자열 분할 시 무조건 정규화(NormalizeIpInput)를 거쳐 동일한 포맷으로 맞춤
inline std::vector<std::wstring> SplitIps(const std::wstring& s) {
    std::vector<std::wstring> tokens;
    std::wstring token;
    std::wstringstream tokenStream(s);
    while (std::getline(tokenStream, token, L',')) {
        if (!token.empty()) {
            tokens.push_back(NormalizeIpInput(token));
        }
    }
    return tokens;
}

// [내부 헬퍼 함수] 벡터의 IP들을 다시 콤마로 연결
inline std::wstring JoinIps(const std::vector<std::wstring>& tokens) {
    std::wstring result = L"";
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0) result += L",";
        result += tokens[i];
    }
    return result;
}

// [내부 헬퍼 함수] 신규 규칙 생성
inline bool CreateNewFirewallRule(INetFwRules* pFwRules, const std::wstring& ips) {
    INetFwRule* pNewRule = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pNewRule);
    
    if (FAILED(hr) || pNewRule == nullptr) return false;

    pNewRule->put_Name(_bstr_t(FIXED_RULE_NAME));
    pNewRule->put_Description(_bstr_t(FIXED_RULE_DESC));
    pNewRule->put_Action(NET_FW_ACTION_BLOCK);
    pNewRule->put_Direction(NET_FW_RULE_DIR_IN);
    pNewRule->put_Enabled(VARIANT_TRUE);
    pNewRule->put_RemoteAddresses(_bstr_t(ips.c_str()));

    hr = pFwRules->Add(pNewRule);
    pNewRule->Release();

    return SUCCEEDED(hr);
}

/**
 * @brief [add] IP 추가 함수 (중복 IP 무시, 에러 없이 성공)
 * @param ips 콤마(,) 또는 외부 파서로 연결된 IP 문자열
 * @return 성공 시 true
 */
inline bool ApplyFirewallRule(const std::wstring& ips) {
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    INetFwRules* pFwRules = nullptr;
    bool success = false;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (SUCCEEDED(hr)) hr = pNetFwPolicy2->get_Rules(&pFwRules);

    if (SUCCEEDED(hr) && pFwRules) {
        INetFwRule* pFwRule = nullptr;
        _bstr_t bstrRuleName(FIXED_RULE_NAME);
        hr = pFwRules->Item(bstrRuleName, &pFwRule);

        std::vector<std::wstring> newList = SplitIps(ips); // IP 정규화 같이 진행

        if (SUCCEEDED(hr) && pFwRule != nullptr) {
            // 기존 규칙이 있는 경우: 기존 리스트와 병합 (중복 체크)
            BSTR bstrExistingRemotes = nullptr;
            std::wstring existingIps = L"";
            if (SUCCEEDED(pFwRule->get_RemoteAddresses(&bstrExistingRemotes)) && bstrExistingRemotes != nullptr) {
                existingIps = bstrExistingRemotes;
                SysFreeString(bstrExistingRemotes);
            }

            std::vector<std::wstring> currentList = (existingIps != L"*") ? SplitIps(existingIps) : std::vector<std::wstring>();
            bool modified = false;

            for (const auto& ip : newList) {
                if (std::find(currentList.begin(), currentList.end(), ip) == currentList.end()) {
                    currentList.push_back(ip);
                    modified = true;
                }
            }

            if (modified) {
                std::wstring mergedIps = JoinIps(currentList);
                pFwRule->put_RemoteAddresses(_bstr_t(mergedIps.c_str()));
            }
            pFwRule->Release();
            success = true; // 이미 포함되어 있어 수정할 게 없어도 성공 처리
        } 
        else {
            // 규칙이 없는 경우: 신규 생성
            success = CreateNewFirewallRule(pFwRules, JoinIps(newList));
        }
        pFwRules->Release();
    }

    if (pNetFwPolicy2) pNetFwPolicy2->Release();
    return success;
}

/**
 * @brief [remove] 지정된 IP 제거 (없어도 성공, 남은 거 없으면 규칙 삭제)
 * @param removeIps 제거할 IP 문자열 목록 (예: L"192.168.1.100")
 * @return 성공 시 true, 실패 시 false
 */
inline bool RemoveFirewallRuleIps(const std::wstring& removeIps) {
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    INetFwRules* pFwRules = nullptr;
    bool success = false;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (SUCCEEDED(hr)) hr = pNetFwPolicy2->get_Rules(&pFwRules);

    if (SUCCEEDED(hr) && pFwRules) {
        INetFwRule* pFwRule = nullptr;
        _bstr_t bstrRuleName(FIXED_RULE_NAME);

        // 기존 규칙 조회
        hr = pFwRules->Item(bstrRuleName, &pFwRule);

        if (SUCCEEDED(hr) && pFwRule != nullptr) {
            BSTR bstrExistingRemotes = nullptr;
            std::wstring existingIps = L"";
            if (SUCCEEDED(pFwRule->get_RemoteAddresses(&bstrExistingRemotes)) && bstrExistingRemotes != nullptr) {
                existingIps = bstrExistingRemotes;
                SysFreeString(bstrExistingRemotes);
            }

            std::vector<std::wstring> currentList = SplitIps(existingIps);
            std::vector<std::wstring> targetsToRemove = SplitIps(removeIps); // 여기서 삭제 타겟도 자동 정규화됨

            // 현재 리스트에서 제거 대상 IP들을 필터링하여 제외
            std::vector<std::wstring> updatedList;

            for (const auto& ip : currentList) {
                bool shouldRemove = false;
                for (const auto& target : targetsToRemove) {
                    if (ip == target) {
                        shouldRemove = true;
                        break;
                    }
                }
                if (!shouldRemove) {
                    updatedList.push_back(ip);
                }
            }

            // 만약 제거 후 남은 IP가 없다면 규칙 자체를 삭제
            if (updatedList.empty()) {
                pFwRule->Release(); // 삭제 전 객체 해제 필수
                pFwRules->Remove(bstrRuleName);
            } 
            else {
                // 규칙을 지웠다 만들지 않고, 기존 규칙 객체에 남은 IP만 덮어씌움 (수정)
                std::wstring newRemotes = JoinIps(updatedList);
                pFwRule->put_RemoteAddresses(_bstr_t(newRemotes.c_str()));
                pFwRule->Release();
            }
            success = true; 
        }
        else {
            // 애초에 규칙 자체가 없는 경우에도 성공으로 처리
            success = true;
        }
        pFwRules->Release();
    }

    if (pNetFwPolicy2) pNetFwPolicy2->Release();
    return success;
}

/**
 * @brief [list] 등록된 차단 IP 리턴 (서브넷 포함)
 * @return std::vector<std::wstring> (규칙이 없으면 빈 벡터 리턴)
 */
inline std::vector<std::wstring> GetBlockedIpList() {
    std::vector<std::wstring> ipList;
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    INetFwRules* pFwRules = nullptr;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (SUCCEEDED(hr)) hr = pNetFwPolicy2->get_Rules(&pFwRules);

    if (SUCCEEDED(hr) && pFwRules) {
        INetFwRule* pFwRule = nullptr;
        _bstr_t bstrRuleName(FIXED_RULE_NAME);

        hr = pFwRules->Item(bstrRuleName, &pFwRule);

        if (SUCCEEDED(hr) && pFwRule != nullptr) {
            BSTR bstrExistingRemotes = nullptr;
            if (SUCCEEDED(pFwRule->get_RemoteAddresses(&bstrExistingRemotes)) && bstrExistingRemotes != nullptr) {
                std::wstring existingIps(bstrExistingRemotes);
                SysFreeString(bstrExistingRemotes);
                if (existingIps != L"*") ipList = SplitIps(existingIps);
            }
            pFwRule->Release();
        }
        pFwRules->Release();
    }
    if (pNetFwPolicy2) pNetFwPolicy2->Release();
    return ipList;
}

/**
 * @brief [clear] 차단 규칙 전체 삭제 (이미 삭제되었거나 없어도 성공 처리)
 * @return 성공 시 true
 */
inline bool ClearAllFirewallRules() {
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    INetFwRules* pFwRules = nullptr;
    bool success = false;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (SUCCEEDED(hr)) hr = pNetFwPolicy2->get_Rules(&pFwRules);

    if (SUCCEEDED(hr) && pFwRules) {
        _bstr_t bstrRuleName(FIXED_RULE_NAME);
        
        // 규칙 삭제 시도 (없어도 에러 코드를 무시하고 성공 처리)
        pFwRules->Remove(bstrRuleName);
        success = true; 
        pFwRules->Release();
    }

    if (pNetFwPolicy2) pNetFwPolicy2->Release();
    return success;
}
