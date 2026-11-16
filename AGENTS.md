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
* `src/utils.h` & `src/utils.cpp`: 순수 유틸리티 (IP/CIDR 파싱, URL 해석, `SplitHostAndPort`, 단일 DNS 질의(`AF_UNSPEC`)). 상태를 가지지 않는 순수 정적(Static) 함수 위주로 구성.
* `src/firewall.h` & `src/firewall.cpp`: WFP 제어 및 핵심 비즈니스 로직. `WhitelistRecord` 데이터 모델 및 WFP 동적 세션 관리.
* `main/cli.cpp` (`bin/r0-fw-cli.exe`): 단발성 기능 테스트를 위한 CLI 진입점. (WFP 동적 세션 유지를 위해 실행 후 프로세스가 대기(block) 상태를 유지하도록 구현)
* `main/daemon.cpp` (`bin/r0-fw-daemon.exe`): Named Pipe (`\\.\pipe\Ransom0_Firewall`) 서버를 구동하고 이벤트 루프를 처리하는 백그라운드 서비스 진입점.

## 4. WFP (Windows Filtering Platform) API & Dual-Stack 원칙

* **Dynamic Session Only:** 롤백의 완벽성을 위해 방화벽 엔진 핸들은 반드시 `FWPM_SESSION_FLAG_DYNAMIC` 플래그를 사용하여 엽니다. 기존 규칙의 백업 및 복원 로직을 작성하지 마십시오.
* **완전 격리(Total Isolation) 원칙:**
  * 기본 차단(Block All)은 `direction` 옵션과 무관하게 항상 **인바운드/아웃바운드 양방향을 100% 완전 차단**합니다.
  * IPv4/IPv6 아웃바운드 레이어(`FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`) 및 인바운드 수신 레이어(`FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`) 모두에 기본 차단 필터를 등록합니다.
  * DNS 기본 허용(UDP/TCP 53)은 도메인 해석을 위해 항상 아웃바운드 레이어에 등록됩니다.
* **화이트리스트 방향성(Directional Whitelist) 원칙:**
  * `direction`(`both`, `out`, `in`) 옵션은 **화이트리스트(Permit 예외 규칙)가 적용되는 통신 방향만 제어**합니다. (기본값: `both`)
  * 아웃바운드 허용 필터는 원격 대상 포트(`FWPM_CONDITION_IP_REMOTE_PORT`)를, 인바운드 허용 필터는 로컬 수신 포트(`FWPM_CONDITION_IP_LOCAL_PORT`)를 조건으로 바인딩합니다.
* **IPv4 & IPv6 듀얼 스택 완전 동기화:**
  * 모든 차단(Block All), DNS 허용(Port 53), 화이트리스트 필터는 IPv4 레이어와 IPv6 레이어 양쪽에 동시에 등록하여 우회 통로를 차단합니다.
  * **바이트 오더 원칙:** WFP에서 IPv4 주소는 Host Byte Order(`ntohl`), IPv6 주소는 Network Byte Order 바이트 배열(`FWP_BYTE_ARRAY16_TYPE`)을 사용하는 규격을 엄격히 준수하십시오.
* **DNS 최적화 원칙:** 도메인 해석 시 `AF_UNSPEC`을 지정한 `getaddrinfo`를 1회만 호출하여 IPv4와 IPv6 목록을 한 번에 추출하고 DNS 왕복 지연을 최소화하십시오.
* **안전한 종료 보장:** RAII (Resource Acquisition Is Initialization) 패턴을 활용하여, C++ 클래스 소멸자에서 WFP 엔진 핸들이 안전하게 닫히도록(`FwpmEngineClose0`) 설계하십시오.

## 5. IPC (Named Pipe) Protocol & JSON 규격

* Named Pipe 이름: `\\.\pipe\Ransom0_Firewall`
* 일반 권한 클라이언트 접근을 위해 SDDL `D:P(A;;GA;;;WD)` 보안 디스크립터를 적용합니다.
* **Action 통합 처리 원칙:** `main/daemon.cpp` 내에서 `on`, `set`, `add`, `remove`, `refresh` 등 공통 화이트리스트 갱신 로직을 중복 복사하지 말고 단일 제어 흐름으로 통합 처리하십시오.
* **상태 전이 규칙:**
  * `on`: 차단이 꺼져 있으면 활성화하며, 응답 `active`는 항상 `true`입니다. 인자가 없으면 마지막 저장된 구성을 적용합니다.
  * `set`: **차단이 비활성화된 상태일 경우 자동으로 활성화하지 않으며, 기존 `active` 상태를 유지합니다.** `whitelist` 키가 생략되면 `refresh`와 동일하게 동작합니다.
  * `add`: 기존 화이트리스트에 새 항목을 추가(중복 자동 제외)하며, 기존 `active` 상태를 유지합니다.
  * `remove`: 기존 화이트리스트에서 지정된 항목을 제거하며, 기존 `active` 상태를 유지합니다. (단, CLI 인자로 지정된 보호 항목은 제거되지 않고 무시됨)
  * `refresh`: 현재 저장된 타겟들의 도메인 IP를 재해석하여 갱신합니다.
  * `off`: 차단 해제 및 `active: false` 고정, 응답 시 `whitelist` 및 `direction` 키를 포함하지 않습니다.
* **Direction(허용 방향) 제어 및 상태 유지 규칙:**
  * `on`, `set`, `add`, `remove` 액션 요청 시 `direction` 키(`"both"`, `"out"`, `"in"`)를 지정하여 화이트리스트 적용 방향을 변경할 수 있습니다.
  * 요청 페이로드에 `direction` 키가 생략되면 기존에 설정된 허용 방향을 그대로 유지합니다. (데몬 시작 시 초기값: `"both"`)
  * `get`, `refresh`, `off` 액션에서는 방향을 변경할 수 없습니다.
  * JSON 응답: 활성/조회 응답(`on`, `set`, `add`, `remove`, `refresh`, `get`) 시 최상위에 현재 적용 중인 `direction: string` 필드가 항상 포함됩니다. (`off` 응답 시에는 제외)
* **CLI 인자 보호 규칙 (Protected Items):** 데몬 구동 시 플래그 없이 전달된 기본 위치 인자들은 삭제 가능한 일반 화이트리스트로 분류되며, `--protect-ip` (또는 `--protect`) 플래그 뒤에 지정된 항목들은 불변의 보호(Protected) 항목으로 취급됩니다. 보호 항목은 `set`이나 `on` 명령으로 새로운 화이트리스트를 덮어쓰거나, `remove` 명령으로 해당 항목의 제거를 요청하더라도 에러를 발생시키지 않고 무시(유지)되어 항상 화이트리스트에 보존됩니다.
* **`WhitelistItem` 표준 JSON 응답 스펙:**
  * 모든 화이트리스트 항목은 `type`, `value`, `data` 구조를 따릅니다.
  * `IPv4`: `data: { "ipv4": string, "port": number, "cidr": number }` (단일 IP는 `cidr: 32`)
  * `IPv6`: `data: { "ipv6": string, "port": number, "cidr": number }` (단일 IP는 `cidr: 128`)
  * `Domain` / `URL`: `data: { "domain": string, "port": number, "ipv4": string[], "ipv6": string[] }`
  * `Port`: `data: { "port": number }`

## 6. Naming Conventions (명명 규칙)

* **Folder/File:** `kebab-case` (ex: `kebab-case.h`, `kebab-case.cpp`)
* **Classes/Structs:** `PascalCase` (ex: `Manager`, `WhitelistRecord`)
* **Functions/Methods:** `PascalCase` (ex: `Enable`, `ParseIpv4`, `SplitHostAndPort`)
* **Variables/Parameters:** `camelCase` (ex: `whitelistTargets`, `engineHandle`)
* **Constants/Macros:** `UPPER_SNAKE_CASE` (ex: `PIPE_NAME`, `MAX_BUFFER_SIZE`)
