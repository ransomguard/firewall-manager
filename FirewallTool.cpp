#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <objbase.h> // COM 초기화

#include "Utils.h"
#include "FirewallTool.h"
#include "PermissionCheck.h"

// [출력 설정] std::wcout, std::wcerr에서 한글 출력을 위한 로케일 설정 헬퍼
struct LocaleInitializer {
    LocaleInitializer() {
        std::locale::global(std::locale("ko_KR.UTF-8"));
        std::wcout.imbue(std::locale());
        std::wcerr.imbue(std::locale());
    }
} globalLocaleInit;

void PrintUsage() {
    std::wcerr << L"[사용법] FirewallTool.exe <block|whitelist> <add|remove|list|clear> [IP1] [IP2] ...\n";
    std::wcerr << L"[예시 1] FirewallTool.exe block add 192.168.1.100 10.0.0.0/24\n";
    std::wcerr << L"[예시 2] FirewallTool.exe block remove 192.168.1.100\n";
    std::wcerr << L"[예시 3] FirewallTool.exe block list\n";
    std::wcerr << L"[예시 4] FirewallTool.exe block clear\n";
    std::wcerr << L"[예시 5] FirewallTool.exe whitelist add 192.168.1.50\n";
    std::wcerr << L"[예시 6] FirewallTool.exe whitelist list\n";
}

int wmain(int argc, wchar_t* argv[]) {
    std::locale::global(std::locale("ko_KR.UTF-8"));

    // 방화벽 수정 권한 사전 체크
    if (!Ransom0::Firewall::Permission::HasFirewallControl()) {
        std::cerr << "[접근 거부] 방화벽 규칙을 수정할 권한이 없습니다.\n"
                  << "관리자 권한(Administrator) 또는 '네트워크 구성 연산자' 권한이 필요합니다.\n";
        return 1;
    }

    if (argc < 3) {
        PrintUsage();
        return 1;
    }

    // Windows 방화벽(BlockManager) 사용을 위한 COM 아파트먼트 초기화
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) {
        std::wcerr << L"[오류] COM 라이브러리 초기화에 실패했습니다.\n";
        return 1;
    }

    std::wstring target = argv[1];  // block or whitelist
    std::wstring command = argv[2]; // add, remove, list, clear

    // 3번째 인자부터 입력된 모든 IP를 하나의 콤마 분리 문자열(std::wstring)로 병합
    std::wstring targetIps = L"";
    for (int i = 3; i < argc; ++i) {
        targetIps += argv[i];
        if (i < argc - 1) {
            targetIps += L",";
        }
    }

    // 인자 유효성 검사 (list와 clear를 제외한 명령어는 IP 인자가 필요함)
    if ((command == L"add" || command == L"remove") && targetIps.empty()) {
        std::wcerr << L"[오류] 처리할 IP 주소를 입력해주세요.\n";
        PrintUsage();
        CoUninitialize();
        return 1;
    }

    bool success = false;

    // ---------------------------------------------------------
    // 1. 방화벽 차단 모듈 (Block) 제어부
    // ---------------------------------------------------------
    if (target == L"block") {
        if (command == L"add") {
            std::wcout << L"[방화벽] 차단 IP 추가 중...\n";
            success = Ransom0::Firewall::Block::AddIps(targetIps);
            if (success) std::wcout << L"완료되었습니다.\n";
        }
        else if (command == L"remove") {
            std::wcout << L"[방화벽] 차단 IP 삭제 중...\n";
            success = Ransom0::Firewall::Block::RemoveIps(targetIps);
            if (success) std::wcout << L"완료되었습니다.\n";
        }
        else if (command == L"list") {
            std::vector<std::wstring> list = Ransom0::Firewall::Block::GetIps();
            std::wcout << L"=== [방화벽] 현재 차단된 IP 목록 (" << list.size() << L"개) ===\n";
            for (const auto& ip : list) {
                std::wcout << ip << L"\n";
            }
            success = true;
        }
        else if (command == L"clear") {
            std::wcout << L"[방화벽] 전체 차단 룰 삭제 중...\n";
            success = Ransom0::Firewall::Block::Clear();
            if (success) std::wcout << L"완료되었습니다.\n";
        }
        else {
            PrintUsage();
        }
    }

    // ---------------------------------------------------------
    // 2. 화이트리스트 모듈 (Whitelist) 제어부
    // ---------------------------------------------------------
    else if (target == L"whitelist") {
        if (command == L"add") {
            std::wcout << L"[화이트리스트] IP 추가 중...\n";
            success = Ransom0::Firewall::Whitelist::AddIps(targetIps);
            if (success) std::wcout << L"완료되었습니다.\n";
        }
        else if (command == L"remove") {
            std::wcout << L"[화이트리스트] IP 삭제 중...\n";
            success = Ransom0::Firewall::Whitelist::RemoveIps(targetIps);
            if (success) std::wcout << L"완료되었습니다.\n";
        }
        else if (command == L"list") {
            std::vector<std::wstring> list = Ransom0::Firewall::Whitelist::Load();
            std::wcout << L"=== [화이트리스트] 등록된 IP 목록 (" << list.size() << L"개) ===\n";
            for (const auto& ip : list) {
                std::wcout << ip << L"\n";
            }
            success = true;
        }
        else if (command == L"clear") {
            std::wcout << L"[화이트리스트] 전체 삭제 중...\n";
            success = Ransom0::Firewall::Whitelist::Clear();
            if (success) std::wcout << L"완료되었습니다.\n";
        }
        else {
            PrintUsage();
        }
    }
    else {
        PrintUsage();
    }

    if (!success && (command == L"add" || command == L"remove" || command == L"clear")) {
        std::wcerr << L"[오류] 작업 수행 중 문제가 발생했습니다.\n";
    }

    // COM 리소스 정리
    CoUninitialize();

    return success ? 0 : 1;
}
