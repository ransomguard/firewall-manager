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

// 내부 전역 상수 (IN / OUT 분리)
const wchar_t* const FIXED_RULE_NAME_IN = L"Block_Malicious_IP_List_IN";
const wchar_t* const FIXED_RULE_NAME_OUT = L"Block_Malicious_IP_List_OUT";
const wchar_t* const FIXED_RULE_DESC_IN = L"Ransom0 엔진에서 관리하는 다중 악성 IP 인바운드 차단 목록입니다.";
const wchar_t* const FIXED_RULE_DESC_OUT = L"Ransom0 엔진에서 관리하는 다중 악성 IP 아웃바운드 차단 목록입니다.";

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

// [내부 헬퍼 함수] 핵심 엔진: 단방향 룰 동기화 헬퍼
inline void SyncSingleRule(INetFwRules* pFwRules, const wchar_t* ruleName, const wchar_t* desc, NET_FW_RULE_DIRECTION dir, const std::wstring& ips) {
    INetFwRule* pRule = nullptr;
    if (SUCCEEDED(pFwRules->Item(_bstr_t(ruleName), &pRule)) && pRule != nullptr) {
        // 기존 룰이 있으면 안전하게 값만 덮어쓰기
        pRule->put_RemoteAddresses(_bstr_t(ips.c_str())); 
        pRule->Release();
    } else if (SUCCEEDED(CoCreateInstance(__uuidof(NetFwRule), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), (void**)&pRule))) {
        pRule->put_Name(_bstr_t(ruleName));
        pRule->put_Description(_bstr_t(desc));
        pRule->put_Action(NET_FW_ACTION_BLOCK);
        pRule->put_Direction(dir);
        pRule->put_Enabled(VARIANT_TRUE);
        
        // ★ 중요: 반드시 Add() 전에 IP 목록을 세팅해야 인터넷 전체 차단 버그를 막을 수 있음
        pRule->put_RemoteAddresses(_bstr_t(ips.c_str())); 
        
        pFwRules->Add(pRule); 
        pRule->Release();
    }
}



// --- [API 함수들] ---

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

        // 마스터 룰(IN 룰)만 읽어오기
        hr = pFwRules->Item(_bstr_t(FIXED_RULE_NAME_IN), &pFwRule);

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
        // 규칙 삭제 시도 (없어도 에러 코드를 무시하고 성공 처리)
        pFwRules->Remove(_bstr_t(FIXED_RULE_NAME_IN));
        pFwRules->Remove(_bstr_t(FIXED_RULE_NAME_OUT));
        success = true;
        pFwRules->Release();
    }

    if (pNetFwPolicy2) pNetFwPolicy2->Release();
    return success;
}

inline bool ApplyFirewallRule(const std::wstring& ips) {
    std::vector<std::wstring> currentList = GetBlockedIpList();
    std::vector<std::wstring> newList = SplitIps(ips);
    
    // 메모리 내에서 중복 없이 병합
    for (const auto& ip : newList) {
        if (std::find(currentList.begin(), currentList.end(), ip) == currentList.end()) {
            currentList.push_back(ip);
        }
    }

    std::wstring finalIps = JoinIps(currentList);
    INetFwPolicy2* pNetFwPolicy2 = nullptr;
    INetFwRules* pFwRules = nullptr;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (SUCCEEDED(hr)) hr = pNetFwPolicy2->get_Rules(&pFwRules);

    if (SUCCEEDED(hr) && pFwRules) {
        SyncSingleRule(pFwRules, FIXED_RULE_NAME_IN, FIXED_RULE_DESC_IN, NET_FW_RULE_DIR_IN, finalIps);
        SyncSingleRule(pFwRules, FIXED_RULE_NAME_OUT, FIXED_RULE_DESC_OUT, NET_FW_RULE_DIR_OUT, finalIps);
        pFwRules->Release();
    }

    if (pNetFwPolicy2) pNetFwPolicy2->Release();
    return true;
}

inline bool RemoveFirewallRuleIps(const std::wstring& removeIps) {
    std::vector<std::wstring> currentList = GetBlockedIpList();
    std::vector<std::wstring> targetsToRemove = SplitIps(removeIps);
    std::vector<std::wstring> updatedList;

    // 메모리 내에서 타겟 삭제
    for (const auto& ip : currentList) {
        if (std::find(targetsToRemove.begin(), targetsToRemove.end(), ip) == targetsToRemove.end()) {
            updatedList.push_back(ip);
        }
    }

    // IP가 더 이상 없으면 룰 자체를 깔끔하게 파기
    if (updatedList.empty()) {
        return ClearAllFirewallRules();
    }

    std::wstring finalIps = JoinIps(updatedList);
    INetFwPolicy2* pNetFwPolicy2 = nullptr; INetFwRules* pFwRules = nullptr;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), NULL, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), (void**)&pNetFwPolicy2);
    if (SUCCEEDED(hr)) hr = pNetFwPolicy2->get_Rules(&pFwRules);

    if (SUCCEEDED(hr) && pFwRules) {
        SyncSingleRule(pFwRules, FIXED_RULE_NAME_IN, FIXED_RULE_DESC_IN, NET_FW_RULE_DIR_IN, finalIps);
        SyncSingleRule(pFwRules, FIXED_RULE_NAME_OUT, FIXED_RULE_DESC_OUT, NET_FW_RULE_DIR_OUT, finalIps);
        pFwRules->Release();
    }
    if (pNetFwPolicy2) pNetFwPolicy2->Release();
    return true;
}
