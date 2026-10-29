# 1. CMake 최소 버전 및 프로젝트 이름 지정
cmake_minimum_required(VERSION 3.15)
project(Ransom0_Firewall LANGUAGES CXX)

# 2. C++ 표준 설정 (C++17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 🎯 실행 파일(.exe)이 생성되는 출력 위치를 프로젝트 루트로 강제 고정
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}")

# 3. 코어 모듈 라이브러리화 (컴파일 최적화)
# src 안의 파일들을 CLI와 Daemon에서 두 번 컴파일하지 않도록 하나의 정적 라이브러리로 묶습니다.
add_library(FirewallCore STATIC
    src/firewall.cpp
    src/permission.cpp
    src/utils.cpp
)

# 4. 헤더 탐색 경로 설정
# PUBLIC으로 설정하면, 이 코어 라이브러리를 사용하는 CLI와 데몬에도 경로가 자동 상속됩니다.
target_include_directories(FirewallCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

# 5. 필수 Windows 시스템 라이브러리 링크 (WFP, Winsock, 권한)
target_link_libraries(FirewallCore PUBLIC
    Fwpuclnt
    Ws2_32
    Advapi32
)

# 6. MSVC 컴파일러 전용 옵션 (UTF-8 인코딩 및 예외 처리)
if(MSVC)
    target_compile_options(FirewallCore PUBLIC /utf-8 /EHsc /W3)
endif()

# ==============================================================
# 🎯 최종 실행 파일 (Targets)
# ==============================================================

# 타겟 1: CLI
add_executable(Ransom0_Firewall_CLI main_cli.cpp)
target_link_libraries(Ransom0_Firewall_CLI PRIVATE FirewallCore)

# 타겟 2: 백그라운드 통신 데몬
add_executable(Ransom0_Firewall_Daemon main_daemon.cpp)
target_link_libraries(Ransom0_Firewall_Daemon PRIVATE FirewallCore)
