#pragma once        // 중복 정의 에러 차단

#include <windows.h>      // CreateNamedPipeW, ConnectNamedPipe, ReadFile, WriteFile
#include <objbase.h>      // CoInitializeEx, CoUninitialize
#include <sddl.h>         // ConvertStringSecurityDescriptorToSecurityDescriptorA
#include <string>         // std::string, std::wstring
#include <vector>         // std::vector
#include <sstream>        // std::ostringstream
#include <thread>         // std::thread (멀티스레딩)

#include "nlohmann/json.hpp"
#include "FirewallTool.h"

// 편의를 위해 json 네임스페이스 단축
using json = nlohmann::json;

namespace Ransom0 {
    namespace Firewall {
        class Pipe {
        private:
            static const DWORD PIPE_BUFFER_SIZE = 65536; // 64KB 버퍼

            // UTF-8 std::string -> UTF-16 std::wstring 변환 (이건 윈도우 API용이므로 그대로 유지)
            static inline std::wstring Utf8ToWstring(const std::string& str) {
                if (str.empty()) return L"";
                int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), NULL, 0);
                if (sizeNeeded <= 0) return L"";
                std::wstring wstr(sizeNeeded, 0);
                MultiByteToWideChar(CP_UTF8, 0, str.data(), (int)str.size(), &wstr[0], sizeNeeded);
                return wstr;
            }

            // UTF-16 std::wstring -> UTF-8 std::string 변환
            static inline std::string WstringToUtf8(const std::wstring& wstr) {
                if (wstr.empty()) return "";
                int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), NULL, 0, NULL, NULL);
                if (sizeNeeded <= 0) return "";
                std::string str(sizeNeeded, 0);
                WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(), &str[0], sizeNeeded, NULL, NULL);
                return str;
            }

        public:
            /**
             * @brief JSON 요청 문자열을 파싱하여 방화벽/화이트리스트 명령을 수행하고 JSON 응답 문자열을 반환합니다.
             * @param jsonRequest 클라이언트로부터 수신한 UTF-8 JSON 문자열
             *        예: {"target":"block","action":"add","ips":["192.168.1.100","10.0.0.0/24"]}
             *        예: {"target":"whitelist","action":"list"}
             * @return UTF-8 JSON 응답 문자열, add/remove/list 모두 ips가 포함되며, 업데이트 목록이 아닌 전체 목록, 마지막에 \\n 포함
             *        예: {"success":true,"message":"string",ips:["192.168.1.100","10.0.0.0/24"]}
             *        예: {"success":false,"message":"string"}
             */
            static inline std::string ProcessRequest(const std::string& jsonString) {
                json req; // 요청을 파싱할 JSON 객체
                json res; // 응답을 담을 JSON 객체

                try {
                    // 1. JSON 문자열 파싱 (try-catch로 포맷 에러 자동 방어)
                    req = json::parse(jsonString);

                    // 2. 필수 필드 검사
                    if (!req.contains("target") || !req.contains("action")) {
                        throw std::invalid_argument("Missing 'target' or 'action' fields.");
                    }

                    std::string target = req["target"];
                    std::string action = req["action"];
                    
                    // Named Pipe로 받은 IPs (단일 문자열 또는 배열 모두 처리)
                    std::wstring targetIps = L""; 
                    
                    if (req.contains("ips")) {
                        if (req["ips"].is_array()) {
                            // 배열인 경우 (예: ["1.1.1.1", "2.2.2.2"]) -> 콤마로 연결
                            std::string combined = "";
                            for (const auto& ip : req["ips"]) {
                                if (!combined.empty()) combined += ",";
                                combined += ip.get<std::string>();
                            }
                            targetIps = Utf8ToWstring(combined);
                        } else if (req["ips"].is_string()) {
                            // 단일 문자열인 경우 (예: "1.1.1.1, 2.2.2.2")
                            targetIps = Utf8ToWstring(req["ips"].get<std::string>());
                        }
                    }

                    // 3. 로직 분기
                    if (target == "block") {
                        if (action == "add") {
                            bool ok = Firewall::Block::AddIps(targetIps);
                            res["success"] = ok;
                            res["message"] = ok ? "Block IPs added." : "Failed to add block IPs.";
                        } 
                        else if (action == "remove") {
                            bool ok = Firewall::Block::RemoveIps(targetIps);
                            res["success"] = ok;
                            res["message"] = ok ? "Block IPs removed." : "Failed to remove block IPs.";
                        }
                        else if (action == "list") {
                            res["success"] = true;
                            res["message"] = "Block IP list retrieved.";
                        }
                        else {
                            throw std::invalid_argument("Unknown action for block");
                        }

                        // 성공 시 갱신된 리스트 반환
                        if (res["success"] == true) {
                            std::vector<std::wstring> list = Firewall::Block::GetIps();
                            res["ips"] = json::array();
                            for (const auto& w_ip : list) {
                                res["ips"].push_back(WstringToUtf8(w_ip));
                            }
                        }
                    } 
                    else if (target == "whitelist") {
                        if (action == "add") {
                            bool ok = Firewall::Whitelist::AddIps(targetIps);
                            res["success"] = ok;
                            res["message"] = ok ? "Whitelist IPs added." : "Failed to add whitelist IPs.";
                        } 
                        else if (action == "remove") {
                            bool ok = Firewall::Whitelist::RemoveIps(targetIps);
                            res["success"] = ok;
                            res["message"] = ok ? "Whitelist IPs removed." : "Failed to remove whitelist IPs.";
                        }
                        else if (action == "list") {
                            res["success"] = true;
                            res["message"] = "Whitelist IP list retrieved.";
                        }
                        else {
                            throw std::invalid_argument("Unknown action for whitelist");
                        }

                        // 성공 시 갱신된 리스트 반환
                        if (res["success"] == true) {
                            std::vector<std::wstring> list = Firewall::Whitelist::Load();
                            res["ips"] = json::array();
                            for (const auto& w_ip : list) {
                                res["ips"].push_back(WstringToUtf8(w_ip));
                            }
                        }
                    } 
                    else {
                        throw std::invalid_argument("Unknown target");
                    }
                } 
                // JSON 파싱 실패 또는 수동 throw 에러 처리
                catch (const std::exception& e) { 
                    res["success"] = false;
                    res["message"] = std::string("Error: ") + e.what();
                }

                // 4. 최종 JSON 객체를 문자열(UTF-8)로 직렬화하여 반환 (\n 포함)
                return res.dump() + "\n"; 
            }

            /**
             * @brief 단일 클라이언트 파이프 연결에 대해 요청을 읽고 처리 후 응답을 전송합니다.
             * @param hPipe 연결된 Named Pipe 핸들
             */
            static inline void HandleClientConnection(HANDLE hPipe) {
                std::vector<char> buffer(PIPE_BUFFER_SIZE, 0);
                DWORD bytesRead = 0;

                BOOL readOk = ReadFile(
                    hPipe,
                    buffer.data(),
                    (DWORD)(buffer.size() - 1),
                    &bytesRead,
                    NULL
                );

                if (readOk && bytesRead > 0) {
                    std::string request(buffer.data(), bytesRead);
                    std::string response = ProcessRequest(request);

                    DWORD bytesWritten = 0;
                    WriteFile(
                        hPipe,
                        response.data(),
                        (DWORD)response.size(),
                        &bytesWritten,
                        NULL
                    );
                    FlushFileBuffers(hPipe);
                }
            }

            /**
             * @brief Named Pipe 서버 루프를 실행하여 멀티스레드로 클라이언트 요청을 지속 처리합니다.
             * @param pipeName 생성할 Named Pipe 경로
             * @return 서버 시작 실패 시 false
             */
            static inline bool RunServer(const wchar_t* pipeName) {
                // [해결 1] 권한 문제 해결: 모든 사용자(World)에게 파이프 접근(읽기/쓰기) 권한 부여
                SECURITY_ATTRIBUTES sa;
                sa.nLength = sizeof(SECURITY_ATTRIBUTES);
                sa.bInheritHandle = FALSE;

                // SDDL을 이용해 보안 디스크립터 생성 (WD = Everyone, GA = Generic All)
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorA(
                    "D:(A;;GA;;;WD)", 
                    SDDL_REVISION_1, 
                    &sa.lpSecurityDescriptor, 
                    NULL)) {
                    return false;
                }

                while (true) {
                    // 보안 속성(&sa)을 적용하여 파이프 인스턴스 생성
                    HANDLE hPipe = CreateNamedPipeW(
                        pipeName,
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                        PIPE_UNLIMITED_INSTANCES,
                        PIPE_BUFFER_SIZE,
                        PIPE_BUFFER_SIZE,
                        0,
                        &sa // 일반 권한인 UI 앱 등에서 접근 가능하도록
                    );

                    if (hPipe == INVALID_HANDLE_VALUE) {
                        LocalFree(sa.lpSecurityDescriptor);
                        return false;
                    }

                    // 클라이언트 연결 대기 (이미 연결된 경우 ERROR_PIPE_CONNECTED)
                    BOOL connected = ConnectNamedPipe(hPipe, NULL) ?
                        TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

                    if (connected) {
                        // 새로운 스레드를 생성하여 비동기 처리
                        std::thread([hPipe]() {
                            // 새 스레드 내부에서 방화벽(COM 객체)을 다루기 위한 COM 아파트먼트 초기화
                            HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

                            // 요청 처리 로직 실행
                            HandleClientConnection(hPipe);

                            // 처리가 완료되면 해당 파이프 인스턴스 해제
                            DisconnectNamedPipe(hPipe);
                            CloseHandle(hPipe);

                            // COM 리소스 정리
                            if (SUCCEEDED(hr)) {
                                CoUninitialize();
                            }
                        }).detach(); // 메인 스레드와 완전히 분리하여 병렬로 백그라운드 실행
                    } else {
                        // 연결 실패 시 핸들 즉시 반환
                        CloseHandle(hPipe);
                    }
                }

                LocalFree(sa.lpSecurityDescriptor);
                return true;
            }
        };
    }
}
