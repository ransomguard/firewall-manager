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
        std::cout << "Usage: firewall_cli [whitelist_ip_or_domain_1] [whitelist_ip_or_domain_2] ...\n";
        WSACleanup();
        return 1;
    }

    Ransom0::Firewall::Manager fwManager;
    std::vector<std::string> targets;
    for (int i = 1; i < argc; ++i) targets.push_back(argv[i]);

    std::vector<Ransom0::Firewall::WhitelistRecord> records;

    if (!fwManager.Enable()) {
        std::cerr << "[-] 방화벽 활성화 실패.\n";
    } else if (!fwManager.setWhitelist(targets, &records)) {
        std::cerr << "[-] 방화벽 화이트리스트 설정 실패.\n";
    } else {
        std::cout << "\n[ Whitelist Details ]\n";
        for (const auto& r : records) {
            std::cout << " - " << r.value << " (" << r.type << ")\n";
            
            // 도메인일 경우 해석된 IPv4, IPv6 목록을 서브 트리로 출력
            if (r.type == "domain") {
                for (const auto& ip : r.resolvedIpv4) {
                    std::cout << "   => [IPv4] " << ip << "\n";
                }
                for (const auto& ip : r.resolvedIpv6) {
                    std::cout << "   => [IPv6] " << ip << "\n";
                }
            }
        }
        std::cout << "\n============================================\n";
        std::cout << "   방화벽 차단 모드가 활성화되었습니다.\n";
        std::cout << "   [!] 종료하려면 Ctrl+C를 누르세요.\n";
        std::cout << "============================================\n";

        // 무한 대기 (Ctrl+C로 종료)
        // 스레드를 Blocking 상태로 만들어 CPU 점유율 0%로 프로세스 생명만 유지
        std::promise<void>().get_future().wait();
        fwManager.Disable();
    }

    WSACleanup();
    return 0;
}
