#include <iostream>
#include <string>
#include <windows.h>
#include <objbase.h> // COM 초기화

#include "PermissionCheck.h"
#include "PipeServer.h"

// 파이프명
const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\Ransom0Firewall";

// [출력 설정] std::wcout, std::wcerr에서 한글 출력을 위한 로케일 설정 헬퍼
struct LocaleInitializer {
    LocaleInitializer() {
        std::locale::global(std::locale("ko_KR.UTF-8"));
        std::wcout.imbue(std::locale());
        std::wcerr.imbue(std::locale());
    }
} globalLocaleInit;

int wmain(int argc, wchar_t* argv[]) {
    std::locale::global(std::locale("ko_KR.UTF-8"));

    // 1. 방화벽 수정 권한 사전 체크
    if (!Ransom0::Firewall::Permission::HasFirewallControl()) {
        std::wcerr << L"[접근 거부] 방화벽 규칙을 수정할 권한이 없습니다.\n"
                   << L"관리자 권한(Administrator) 또는 '네트워크 구성 연산자' 권한이 필요합니다.\n";
        return 1;
    }

    // 2. Windows 방화벽(BlockManager) 사용을 위한 COM 아파트먼트 초기화
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (FAILED(hr)) {
        std::wcerr << L"[오류] COM 라이브러리 초기화에 실패했습니다.\n";
        return 1;
    }

    std::wcout << L"=== [Ransom0 방화벽 Named Pipe 서버 시작] ===\n";
    std::wcout << L"- 파이프 경로: " << PIPE_NAME << L"\n";
    std::wcout << L"- 클라이언트 JSON 요청 대기 중... (종료하려면 Ctrl+C)\n";

    // 3. Named Pipe 서버 루프 실행
    bool serverResult = Ransom0::Firewall::Pipe::RunServer(PIPE_NAME);
    if (!serverResult) {
        std::wcerr << L"[오류] Named Pipe 생성 또는 서버 실행에 실패했습니다. (Error Code: " << GetLastError() << L")\n";
    }

    // COM 리소스 정리
    CoUninitialize();

    return serverResult ? 0 : 1;
}
