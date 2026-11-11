#include <iostream>
#include <string>
#include <vector>
#include <future>
#include <winsock2.h>
#include <windows.h>

#include "permission.h"
#include "firewall.h"



int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    if (!Ransom0::Firewall::Permission::HasFirewallControl()) {
        std::cerr << "[-] [거부됨] 방화벽을 제어하려면 '관리자 권한'이 필요합니다.\n";
        return 1;
    }

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[-] Winsock 초기화 실패!\n";
        return 1;
    }

    if (argc < 2) {
        std::cout << "Usage: r0-fw-cli.exe [-d <both|out|in>] [target_1] [target_2] ...\n";
        std::cout << "Options:\n";
        std::cout << "  -d, --direction <dir>  화이트리스트 허용 방향 설정 (both, out, in / 기본값: both)\n";
        std::cout << "\n";
        std::cout << "Examples:\n";
        std::cout << "  r0-fw-cli.exe 192.168.0.1 fd00::1\n";
        std::cout << "  r0-fw-cli.exe -d in 192.168.0.1 fd00::1\n";
        std::cout << "  r0-fw-cli.exe -d out 192.168.0.1 fd00::1\n";
        std::cout << "  r0-fw-cli.exe 192.168.0.1:8080 [fd00::1]:8443\n";
        std::cout << "  r0-fw-cli.exe 192.168.0.0/24 10.0.0.0/8 fd00::/64\n";
        std::cout << "  r0-fw-cli.exe 192.168.0.0/24:22 [fd00::/64]:8080\n";
        std::cout << "  r0-fw-cli.exe example.com example.com:443\n";
        std::cout << "  r0-fw-cli.exe 8080 *:8080\n";
        std::cout << "  r0-fw-cli.exe https://api.github.com/v1 http://192.168.1.1:8080/path\n";
        WSACleanup();
        return 1;
    }

    Ransom0::Firewall::Direction direction = Ransom0::Firewall::Direction::Both;
    std::vector<std::string> targets;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-d" || arg == "--direction") {
            if (i + 1 < argc) {
                std::string dirVal = argv[++i];
                if (!Ransom0::Firewall::ParseDirection(dirVal, direction)) {
                    std::cerr << "[-] 알 수 없는 direction 값: " << dirVal << " (both, out, in 중 선택)\n";
                    WSACleanup();
                    return 1;
                }
            } else {
                std::cerr << "[-] -d/--direction 옵션 뒤에 방향(both, out, in)을 지정해야 합니다.\n";
                WSACleanup();
                return 1;
            }
        } else if (arg == "--in" || arg == "--inbound") {
            direction = Ransom0::Firewall::Direction::Inbound;
        } else if (arg == "--out" || arg == "--outbound") {
            direction = Ransom0::Firewall::Direction::Outbound;
        } else if (arg == "--both" || arg == "--all") {
            direction = Ransom0::Firewall::Direction::Both;
        } else {
            targets.push_back(arg);
        }
    }

    Ransom0::Firewall::Manager fwManager;
    std::vector<Ransom0::Firewall::WhitelistRecord> records;

    if (!fwManager.Enable(direction)) {
        std::cerr << "[-] 방화벽 활성화 실패.\n";
    } else if (!fwManager.setWhitelist(targets, &records)) {
        std::cerr << "[-] 방화벽 화이트리스트 설정 실패.\n";
    } else {
        std::cout << "[+] 트래픽 방향: " << Ransom0::Firewall::DirectionToString(direction) << "\n";
        std::cout << "\n[ Whitelist Details ]\n";
        for (const auto& r : records) {
            std::cout << " - " << r.value << " (" << r.type;
            if (r.port != 0) std::cout << ", Port: " << r.port;
            std::cout << ")\n";

            if (r.type == "domain" || r.type == "url") {
                for (const auto& ip : r.resolvedIpv4) {
                    std::cout << "   => [IPv4] " << ip << "\n";
                }
                for (const auto& ip : r.resolvedIpv6) {
                    std::cout << "   => [IPv6] " << ip << "\n";
                }
            } else if (r.type == "ipv4") {
                std::cout << "   => [IPv4] " << r.ip << "/" << static_cast<int>(r.cidr) << "\n";
            } else if (r.type == "ipv6") {
                std::cout << "   => [IPv6] " << r.ip << "/" << static_cast<int>(r.cidr) << "\n";
            }
        }
        std::cout << "\n============================================\n";
        std::cout << "   방화벽 차단 모드가 활성화되었습니다. (" << Ransom0::Firewall::DirectionToString(direction) << ")\n";
        std::cout << "   [!] 종료하려면 Ctrl+C를 누르세요.\n";
        std::cout << "============================================\n";

        // 무한 대기 (Ctrl+C로 종료)
        std::promise<void>().get_future().wait();
        fwManager.Disable();
    }

    WSACleanup();
    return 0;
}
