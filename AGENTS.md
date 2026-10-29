# Ransom0 (RansomGuard) C/C++ Development Conventions

이 문서는 Ransom0 프로젝트의 방화벽(Network Isolation) 모듈 및 C/C++ 데몬을 개발할 때 AI 에이전트가 반드시 준수해야 하는 코딩 스탠다드와 아키텍처 규칙입니다.
모든 코드 생성 및 리팩토링은 아래의 컨벤션을 엄격히 따릅니다.

## 1. Namespace Rules (네임스페이스 규칙)

모든 커스텀 코드는 다른 앱 및 서비스와의 충돌을 방지하기 위해 반드시 `Ransom0` 네임스페이스 하위에 격리되어야 합니다.

* **Core Logic:** `Ransom0::Firewall`
* **Utility/Helpers:** `Ransom0::Firewall::Utils`
* **전역 공간(Global Namespace) 오염 금지:** `using namespace std;` 등의 사용을 헤더 파일에서 절대 금지합니다.

## 2. Header Isolation & Encapsulation (헤더 격리 및 은닉 원칙)

외부에 노출되는 Public Header(`.h`)는 내부 구현을 완벽히 숨겨야 합니다.

* **Windows Header 금지:** `firewall.h` 등 헤더 파일 안에는 `<windows.h>`, `<fwpmu.h>`, `<winsock2.h>` 같은 OS 종속적인 무거운 헤더를 절대 `include` 하지 마십시오.
* **Pimpl 이디엄 활용:** WFP 내부 구조체(`FWPM_FILTER0`, `HANDLE` 등)나 Named Pipe 핸들은 헤더에 노출하지 말고, 전방 선언(Forward Declaration)이나 Pimpl(Pointer to implementation) 패턴, 혹은 `void*` 로 숨긴 뒤 `.cpp` 내부에서만 캐스팅하여 사용하십시오.
* **상수 및 매크로 은닉:** 내부에서만 쓰는 WFP 가중치(Weight)나 파이프 이름 상수 등은 헤더가 아닌 `.cpp` 파일 상단의 익명 네임스페이스(Anonymous Namespace)에 정의하십시오.

## 3. Project Structure & Entry Points (파일 및 실행 구조)

기능은 명확히 분리되며, 실행을 위한 진입점(Entry Point)은 항상 두 가지로 유지합니다. 코드 제안 시 이 구조를 훼손하지 마십시오.
새로운 파일 추가 시에도 같은 구조로 생성하십시오.

* `src/permission.h` & `src/permission.cpp`: 네트워크 제어 권한(Administrator, Network Configuration Operators) 검증 로직. WFP API 접근 전 권한 확인 수행.
* `src/utils.h` & `src/utils.cpp`: 순수 유틸리티 (IP 파싱, 타입 변환 등). 상태를 가지지 않는 정적(Static) 함수 위주로 구성.
* `src/firewall.h` & `src/firewall.cpp`: WFP 제어 및 핵심 비즈니스 로직.
* `main_cli.cpp`: 단발성 기능 테스트를 위한 CLI 진입점. (WFP 동적 세션 유지를 위해 실행 후 프로세스가 대기(block) 상태를 유지하도록 구현)
* `main_daemon.cpp`: Electron 프론트엔드와 통신하기 위한 백그라운드 서비스 진입점. Named Pipe (`\\.\pipe\Ransom0Firewall`) 서버를 구동하고 이벤트 루프를 처리.

## 4. WFP (Windows Filtering Platform) API 원칙

* **Dynamic Session Only:** 롤백의 완벽성을 위해 방화벽 엔진 핸들은 반드시 `FWPM_SESSION_FLAG_DYNAMIC` 플래그를 사용하여 엽니다. 기존 규칙의 백업 및 복원 로직을 작성하지 마십시오.
* **안전한 종료 보장:** RAII (Resource Acquisition Is Initialization) 패턴을 활용하여, C++ 클래스 소멸자에서 WFP 엔진 핸들이 안전하게 닫히도록(`FwpmEngineClose0`) 설계하십시오.

## 5. IPC (Named Pipe) Communication

* Electron 프론트엔드와의 통신은 비동기(Overlapped I/O) 또는 멀티스레드 기반의 Named Pipe로 구현하여 병목을 방지하십시오.
* 데이터 교환 포맷은 JSON 직렬화를 사용합니다.

## 6. Naming Conventions (명명 규칙)

* **Folder/File:** `kebab-case` (ex: `kebab-case.h`, `kebab-case.cpp`)
* **Classes/Structs:** `PascalCase` (ex: `FirewallManager`)
* **Functions/Methods:** `PascalCase` (ex: `EnableIsolation`, `ParseIpAddress`)
* **Variables/Parameters:** `camelCase` (ex: `whitelistIps`, `engineHandle`)
* **Constants/Macros:** `UPPER_SNAKE_CASE` (ex: `MAX_BUFFER_SIZE`)
