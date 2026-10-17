#pragma once        // 중복 정의 에러 차단

#include <string>         // std::wstring
#include <vector>         // std::vector
#include <algorithm>      // std::find

#include "Utils.h"        // 공통 IP 파싱 및 헬퍼 함수

namespace Ransom0 {
    namespace Firewall {
        namespace Core {
            class Whitelist {
            private:
                static constexpr const wchar_t* const WHITELIST_FILE = L"whitelist.txt";

            public:
                /**
                 * @brief [화이트리스트] 파일에서 화이트리스트 IP 목록 읽기 및 자동 정규화
                 * @return 화이트리스트 IP 벡터 (정규화된 CIDR 형식)
                 */
                static inline std::vector<std::wstring> Load() {
                    std::vector<std::wstring> whitelist;
                    FILE* file = nullptr;

                    // 1. 와이드 문자열(UTF-16) 경로를 지원하는 _wfopen_s 사용
                    if (_wfopen_s(&file, WHITELIST_FILE, L"rt") != 0 || file == nullptr) {
                        return whitelist;
                    }

                    // 파일 내용(IP 주소)은 순수 ASCII 이므로 char 버퍼와 fgets를 그대로 사용하여 성능을 극대화합니다.
                    char buffer[1024];

                    // 2. fgets로 버퍼 재사용하며 빠르게 한 줄씩 읽기
                    while (fgets(buffer, sizeof(buffer), file)) {
                        std::string line(buffer);

                        // 앞 공백 찾기
                        size_t start = line.find_first_not_of(" \t\r\n");
                        // 빈 줄이거나 주석('#')이면 즉시 패스
                        if (start == std::string::npos || line[start] == '#') continue;

                        // 뒤 공백 찾기
                        size_t end = line.find_last_not_of(" \t\r\n");

                        // 3. substr 복사 없이 즉시 std::wstring 생성 (Zero-Copy 형변환)
                        std::wstring wline(line.begin() + start, line.begin() + end + 1);

                        // [버그 픽스] '=' 덮어쓰기 방지 및 파일의 모든 줄을 누적(insert) 하도록 수정
                        std::vector<std::wstring> parts = Ransom0::Firewall::Utils::SplitIps(wline);
                        whitelist.insert(whitelist.end(), parts.begin(), parts.end());
                    }

                    fclose(file);

                    // 5. C++ 정석 기법: 한 번에 정렬하고 중복 요소 일괄 삭제 (Sort & Erase Unique)
                    if (!whitelist.empty()) {
                        std::sort(whitelist.begin(), whitelist.end());
                        whitelist.erase(std::unique(whitelist.begin(), whitelist.end()), whitelist.end());
                    }

                    return whitelist;
                }

                /**
                 * @brief [화이트리스트] 화이트리스트 IP 목록을 CIDR 형식으로 변환하여 파일로 저장
                 * @param whitelist 기존 화이트리스트 배열 (참조(&)로 전달받아 직접 수정: 정렬 및 중복 제거)
                 * @return 저장 성공 여부 (성공 시 true, 실패 시 false)
                 */
                static inline bool Save(std::vector<std::wstring>& whitelist) {
                    // 1. [방어 로직 추가] 파일에 쓰기 직전, 만약의 사태를 대비해 최종 정렬 및 중복 제거
                    if (!whitelist.empty()) {
                        std::sort(whitelist.begin(), whitelist.end());
                        whitelist.erase(std::unique(whitelist.begin(), whitelist.end()), whitelist.end());
                    }

                    FILE* file = nullptr;

                    // 1. ofstream 대신 가볍고 빠른 C 표준 API 사용
                    if (_wfopen_s(&file, WHITELIST_FILE, L"wt") != 0 || file == nullptr) {
                        return false;
                    }

                    // 2. 스택(Stack) 버퍼 재사용 (동적 할당 Zero)
                    // IP 형식의 최대 길이(예: "255.255.255.255/255.255.255.255\n\0")는 33자이므로 64바이트면 아주 넉넉함
                    char buffer[64];

                    for (const auto& ip : whitelist) {
                        std::wstring denormalized = Ransom0::Firewall::Utils::NormalizeToCidrFormat(ip);
                        size_t len = denormalized.length();

                        // 버퍼 오버플로우 안전장치 (그럴 일은 없겠지만 방어 코드 작성)
                        if (len >= sizeof(buffer) - 2) continue;

                        // 3. std::string 객체를 새로 만들지 않고, wstring의 문자를 바로 ASCII로 캐스팅하여 스택 버퍼에 복사
                        // (IP 주소는 숫자, '.', '/' 등 순수 ASCII 문자만 존재하므로 이 캐스팅이 가장 빠르고 안전함)
                        for (size_t i = 0; i < len; ++i) {
                            buffer[i] = static_cast<char>(denormalized[i]);
                        }

                        // 4. 직접 줄바꿈(\n)과 C-스타일 문자열 종료(\0) 추가
                        buffer[len] = '\n';
                        buffer[len + 1] = '\0';

                        // 5. 만들어진 버퍼를 파일에 한 번에 출력
                        fputs(buffer, file);
                    }

                    fclose(file);

                    return true;
                }

                /**
                 * @brief [화이트리스트] 메모리 상의 IP 화이트리스트 전체 초기화(삭제)
                 * @param whitelist 기존 화이트리스트 배열 (참조(&)로 전달받아 직접 수정)
                 * @return 실제로 삭제가 수행되어 배열이 비워졌다면 true, 아니면 false
                 */
                static inline bool Clear(std::vector<std::wstring>& whitelist) {
                    if (whitelist.empty()) return false;
                    whitelist.clear();
                    return true;
                }

                /**
                 * @brief [화이트리스트] 메모리 상의 IP 화이트리스트에 새 IP 목록 추가
                 * @param whitelist 기존 화이트리스트 배열 (참조(&)로 전달받아 직접 수정)
                 * @param tokens IP 주소 벡터
                 * @return 실제로 새롭게 추가된 IP가 하나라도 있다면 true, 없으면 false
                 * @note vector 파라미터를 const&로 받아 외부 원본 데이터 훼손 방지 및 내부 정규화 수행
                 */
                static inline bool AddIps(std::vector<std::wstring>& whitelist, const std::vector<std::wstring>& tokens) {
                    if (tokens.empty()) return false;

                    // 1. 변경 여부 확인을 위해 삽입 전 원래 배열 크기 저장
                    size_t originalSize = whitelist.size();

                    // 2. 루프를 돌며 find 하지 않고, 배열 끝에 일괄 통째로 이어 붙이기 (Bulk Insert)
                    // [버그 픽스] 화이트리스트에 새 IP를 넣을 때도 반드시 정규화(CIDR 변환) 수행
                    for (const auto& ip : tokens) {
                        whitelist.push_back(Ransom0::Firewall::Utils::NormalizeToCidrFormat(ip));
                    }

                    // 3. 전체 정렬 후 중복된 요소 일괄 삭제 (Sort & Erase Unique 패턴)
                    std::sort(whitelist.begin(), whitelist.end());
                    whitelist.erase(std::unique(whitelist.begin(), whitelist.end()), whitelist.end());

                    // 4. 중복이 제거된 후의 최종 크기가 원래 크기보다 크다면, 새로운 IP가 들어갔다는 의미
                    return whitelist.size() > originalSize;
                }

                /**
                 * @brief [화이트리스트] 메모리 상의 IP 화이트리스트에서 특정 IP 목록 제거
                 * @param whitelist 기존 화이트리스트 배열 (참조(&)로 전달받아 직접 수정)
                 * @param tokens IP 주소 벡터
                 * @return 실제로 삭제된 IP가 하나라도 있다면 true, 없으면 false
                 * @note vector 파라미터를 const&로 받아 외부 원본 데이터 훼손 방지 및 내부 정규화 수행
                 */
                static inline bool RemoveIps(std::vector<std::wstring>& whitelist, const std::vector<std::wstring>& tokens) {
                    if (tokens.empty()) return false;

                    // 1. 변경 여부 확인을 위해 삭제 전 원래 크기 저장
                    size_t originalSize = whitelist.size();

                    // 2. 검색 속도 극대화를 위해 삭제 대상(tokens)을 정렬
                    // [버그 픽스] 삭제 대상(tokens) 복사 및 정규화
                    std::vector<std::wstring> targetIps;
                    targetIps.reserve(tokens.size());
                    for (const auto& ip : tokens) {
                        targetIps.push_back(Ransom0::Firewall::Utils::NormalizeToCidrFormat(ip));
                    }
                    std::sort(targetIps.begin(), targetIps.end()); 

                    // 3. [핵심] Erase-Remove Idiom 적용 (새로운 배열 복사 없이 제자리에서 고속 삭제
                    whitelist.erase(
                        std::remove_if(whitelist.begin(), whitelist.end(),
                            [&targetIps](const std::wstring& ip) {
                                // std::binary_search(이분 탐색)를 사용하여 O(log M) 속도로 삭제 대상인지 확인
                                return std::binary_search(targetIps.begin(), targetIps.end(), ip);
                            }
                        ),
                        whitelist.end()
                    );

                    // 4. 삭제가 수행되어 최종 크기가 원래 크기보다 작아졌다면 변경된 것(true)
                    return whitelist.size() < originalSize;
                }

                /**
                 * @brief [화이트리스트] 메모리 상의 IP 화이트리스트에서 특정 IP 또는 서브넷 대역이 화이트리스트에 존재하는지 검사
                 * @param whitelist 기존 화이트리스트 배열 (참조(&)로 전달받아 직접 수정)
                 * @param ip 체크할 IP 주소 문자열 (예: 192.168.0.1 or 192.168.0.0/24)
                 * @return whitelist에 ip가 존재하거나, ip가 whitelist의 서브넷 대역에 포함되면 true, 아니면 false
                 */
                static inline bool IsWhitelisted(const std::vector<std::wstring>& whitelist, const std::wstring& ip) {
                    for (const auto& wIp : whitelist) {
                        if (Ransom0::Firewall::Utils::IsIpInSubnet(ip, wIp)) {
                            return true;
                        }
                    }
                    return false;
                }
            };
        }
    }
}
