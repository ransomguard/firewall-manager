#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include "PermissionCheck.h"
#include "FirewallManager.h"

// 다중 IP를 콤마 문자열로 묶어주는 헬퍼
std::wstring ParseIps(int argc, char* argv[], int startIndex) {
    std::wstring ips = L"";
    for (int i = startIndex; i < argc; ++i) {
        int len = MultiByteToWideChar(CP_ACP, 0, argv[i], -1, NULL, 0);
        std::wstring ip(len, 0);
        MultiByteToWideChar(CP_ACP, 0, argv[i], -1, &ip[0], len);
        if (!ip.empty() && ip.back() == L'\0') ip.pop_back();

        if (!ips.empty()) ips += L",";
        ips += ip;
    }
    return ips;
}

int main(int argc, char* argv[]) {
    std::locale::global(std::locale("ko_KR.UTF-8"));

    // 방화벽 수정 권한 사전 체크
    if (!HasFirewallControlPermission()) {
        std::cerr << "[접근 거부] 방화벽 규칙을 수정할 권한이 없습니다.\n"
                  << "관리자 권한(Administrator) 또는 '네트워크 구성 연산자' 권한이 필요합니다.\n";
        return 1;
    }

    if (argc < 2) {
        std::cerr << "[사용법] FirewallTool.exe <add|remove|list|clear> [IP1] [IP2] ...\n";
        std::cerr << "[예시 1] FirewallTool.exe add 192.168.1.100 10.0.0.0/24\n";
        std::cerr << "[예시 2] FirewallTool.exe remove 192.168.1.100\n";
        std::cerr << "[예시 3] FirewallTool.exe list\n";
        std::cerr << "[예시 4] FirewallTool.exe clear\n";
        return 1;
    }

    std::string command = argv[1];
    
    // list와 clear 명령어는 IP 인자가 필요 없으므로 인자 개수 검증을 다르게 가져갑니다.
    if ((command == "add" || command == "remove") && argc < 3) {
        std::cerr << "[오류] '" << command << "' 명령어는 최소 1개 이상의 IP 인자가 필요합니다.\n";
        return 1;
    }

    // COM 초기화
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        std::cerr << "[오류] COM 초기화 실패\n";
        return 1;
    }

    bool success = false;
    std::wstring targetIps = L"";

    if (command == "add" || command == "remove") {
        targetIps = ParseIps(argc, argv, 2);
        if (command == "add") {
            success = ApplyFirewallRule(targetIps);
        } else {
            success = RemoveFirewallRuleIps(targetIps);
        }

        if (success) {
            std::wcout << L"[성공] '" << std::wstring(command.begin(), command.end()) << L"' 작업 완료. 대상 IP: " << targetIps << L"\n";
        } else {
            std::cerr << "[오류] 작업 처리 중 내부 에러가 발생했습니다.\n";
        }
    } 
    else if (command == "list") {
        // 헤더에 선언된 목록 조회 함수 호출 가정 (예: GetBlockedIpList)
        std::vector<std::wstring> ipList = GetBlockedIpList();
        
        if (ipList.empty()) {
            std::wcout << L"[안내] 등록된 차단 IP가 없거나 규칙(" << FIXED_RULE_NAME << L")이 존재하지 않습니다.\n";
        } else {
            std::wcout << L"[현재 차단된 IP 목록 (" << ipList.size() << L"개)]:\n";
            for (size_t i = 0; i < ipList.size(); ++i) {
                std::wcout << i + 1 << L". " << ipList[i] << L"\n";
            }
        }
        success = true;
    } 
    else if (command == "clear") {
        // 헤더에 선언된 전체 규칙 삭제 함수 호출 가정 (예: ClearAllFirewallRules)
        success = ClearAllFirewallRules();
        if (success) {
            std::wcout << L"[성공] 차단 목록이 모두 초기화(삭제)되었습니다.\n";
        } else {
            std::cerr << "[오류] 초기화 실패 또는 삭제할 규칙이 없습니다.\n";
        }
    } 
    else {
        std::cerr << "[오류] 알 수 없는 명령어입니다. (사용 가능한 명령어: add, remove, list, clear)\n";
        success = false;
    }

    CoUninitialize();
    return success ? 0 : 1;
}
