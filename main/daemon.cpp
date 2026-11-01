#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <sddl.h>

#include <nlohmann/json.hpp>

#include "permission.h"
#include "firewall.h"



int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    if (!Ransom0::Firewall::Permission::HasFirewallControl()) {
        std::cerr << "[FATAL] 관리자 권한이 필요합니다.\n";
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[-] Winsock 초기화 실패!\n";
        return 1;
    }

    std::cout << "[+] Starting Ransom0 Firewall Daemon...\n";
    LPCSTR pipeName = "\\\\.\\pipe\\Ransom0_Firewall";
    Ransom0::Firewall::Manager fwManager;

    std::vector<std::string> globalRawTargets;
    nlohmann::json cachedWhitelistState = nlohmann::json::array();

    // ==========================================
    // 상세 로그 출력을 위한 람다 함수
    // ==========================================
    auto printWhitelistLog = [](const std::string& prefix, const std::vector<Ransom0::Firewall::WhitelistRecord>& records) {
        std::cout << prefix << " 예외 대상: " << records.size() << "개\n";
        for (const auto& r : records) {
            std::cout << "  - " << r.value << " (" << r.type;
            if (r.port != 0) std::cout << ", Port: " << r.port;
            std::cout << ")\n";

            if (r.type == "domain" || r.type == "url") {
                for (const auto& ip : r.resolvedIpv4) std::cout << "    => [IPv4] " << ip << "\n";
                for (const auto& ip : r.resolvedIpv6) std::cout << "    => [IPv6] " << ip << "\n";
            } else if (r.type == "ipv4") {
                std::cout << "    => [IPv4] " << r.ip << "/" << static_cast<int>(r.cidr) << "\n";
            } else if (r.type == "ipv6") {
                std::cout << "    => [IPv6] " << r.ip << "/" << static_cast<int>(r.cidr) << "\n";
            }
        }
        std::cout << std::endl;
    };

    // ==========================================
    // WhitelistRecord 목록을 JSON 캐시 상태로 변환하는 람다 함수
    // ==========================================
    auto recordsToJson = [](const std::vector<Ransom0::Firewall::WhitelistRecord>& records) {
        nlohmann::json state = nlohmann::json::array();
        for (const auto& r : records) {
            nlohmann::json item;
            item["value"] = r.value;
            item["type"] = r.type;

            nlohmann::json data = nlohmann::json::object();
            data["port"] = r.port;
            if (r.type == "ipv4") {
                data["ipv4"] = r.ip;
                data["cidr"] = r.cidr;
            } else if (r.type == "ipv6") {
                data["ipv6"] = r.ip;
                data["cidr"] = r.cidr;
            } else if (r.type == "domain" || r.type == "url") {
                data["domain"] = r.domain;
                data["ipv4"] = r.resolvedIpv4;
                data["ipv6"] = r.resolvedIpv6;
            }
            item["data"] = data;

            state.push_back(item);
        }
        return state;
    };

    // 일반 권한 클라이언트도 관리자 파이프에 접근할 수 있도록 권한 개방
    PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
    SECURITY_ATTRIBUTES sa = { 0 };

    // SDDL을 통해 모든 사용자(WD)에게 풀 권한 부여
    if (
        ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:P(A;;GA;;;WD)",
        SDDL_REVISION_1,
        &pSecurityDescriptor,
        NULL)
    ) {
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSecurityDescriptor;
        sa.bInheritHandle = FALSE;
    }

    // CLI 인자가 주어졌다면 기본적으로 차단을 활성화하고 초기 화이트리스트 구성
    if (argc > 1) {
        std::cout << "[+] CLI 인자 감지됨. 초기 화이트리스트 구성을 시작합니다...\n";

        for (int i = 1; i < argc; ++i) {
            globalRawTargets.push_back(argv[i]);
        }

        std::vector<Ransom0::Firewall::WhitelistRecord> records;
        fwManager.Enable();
        fwManager.setWhitelist(globalRawTargets, &records);

        cachedWhitelistState = recordsToJson(records);
        printWhitelistLog("[+] 방화벽 ON (CLI 초기화).", records);
    }

    while (true) {
        HANDLE hPipe = CreateNamedPipeA(
            pipeName, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 4096, 4096, 0,
            &sa // 위에서 만든 보안 속성 적용
        );

        if (hPipe != INVALID_HANDLE_VALUE) {
            if (ConnectNamedPipe(hPipe, NULL) != FALSE || GetLastError() == ERROR_PIPE_CONNECTED) {
                char buffer[4096] = { 0 };
                DWORD bytesRead;

                // 1. 파이프로 받은 데이터 읽기
                if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                    nlohmann::json response;

                    try {
                        // 2. 들어온 문자열을 JSON 객체로 파싱
                        nlohmann::json payload = nlohmann::json::parse(buffer);
                        std::string action = payload["action"];
                        response["action"] = action;

                        if (action == "on" || action == "set" || action == "refresh") {
                            // Payload에 새로운 whitelist가 있다면 덮어쓰기, 없다면 기존 타겟 유지
                            // on/set 시 whitelist가 없으면 마지막에 설정한 값으로 적용하기 위함
                            // on/set 시 whitelist를 설정하지 않으려면 빈 배열을 보내면 됨
                            // = on 시 whitelist가 없으면 차단 활성화 + refresh 효과와 같음
                            // = set 시 whitelist가 없으면 refresh와 동일하게 동작함
                            if (action != "refresh" && payload.contains("whitelist")) {
                                globalRawTargets = payload["whitelist"].get<std::vector<std::string>>();
                            }

                            // 3. 화이트리스트 설정
                            std::vector<Ransom0::Firewall::WhitelistRecord> records;

                            if (action == "on") fwManager.Enable();
                            fwManager.setWhitelist(globalRawTargets, &records);

                            // 4. 반환된 C++ 구조체를 JSON 객체로 변환하여 캐시에 덮어쓰기
                            cachedWhitelistState = recordsToJson(records);

                            response["success"] = true;
                            response["active"] = (action == "on") ? true : fwManager.IsActive();
                            response["whitelist"] = cachedWhitelistState;

                            if (action == "on") {
                                printWhitelistLog("[+] 방화벽 ON.", records);
                            } else if (action == "set") {
                                printWhitelistLog("[+] 방화벽 SET.", records);
                            } else if (action == "refresh") {
                                printWhitelistLog("[+] 방화벽 REFRESH.", records);
                            }
                        }
                        else if (action == "get") {
                            response["success"] = true;
                            response["active"] = fwManager.IsActive();
                            response["whitelist"] = cachedWhitelistState;
                        }
                        else if (action == "off") {
                            fwManager.Disable();
                            std::cout << "[+] 방화벽 OFF. 롤백 완료.\n\n";
                            response["success"] = true;
                            response["active"] = false;
                        }
                        else {
                            response.erase("action");
                            response["success"] = false;
                            response["message"] = "Unknown action command.";
                        }
                    }
                    catch (const nlohmann::json::exception& e) {
                        std::cerr << "[-] JSON 파싱 에러: " << e.what() << "\n\n";
                        response["success"] = false;
                        response["message"] = std::string("JSON parsing error: ") + e.what();
                    }
                    catch (...) {
                        std::cerr << "[-] 알 수 없는 에러\n\n";
                        response["success"] = false;
                        response["message"] = "Unknown error occurred.";
                    }

                    // 완성된 JSON 문자열을 파이프를 통해 클라이언트로 전송
                    std::string resString = response.dump() + "\n";
                    DWORD written = 0;
                    WriteFile(hPipe, resString.c_str(), (DWORD)resString.length(), &written, NULL);
                    FlushFileBuffers(hPipe);
                }
            }

            // 명령 1개 처리 후 파이프 끊고 다시 대기 (단발성 연결 기준)
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
        }
    }

    if (pSecurityDescriptor) LocalFree(pSecurityDescriptor);
    WSACleanup();
    return 0;
}
