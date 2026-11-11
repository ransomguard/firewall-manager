# Firewall Manager

> [!NOTE]
> Windows 전용이며, 방화벽 룰이 아닌
> `WFP(Windows Filtering Platform)`를 직접 제어합니다.



## Whitelist

기본적으로 네트워크 전체를 차단하며,
지정된 대상과의 통신을 허용합니다.

- IP, Port 기반 화이트리스트 구성
- CIDR 표기법 지원
- 도메인 설정 지원 (IPv4 및 IPv6 동적 구성)
- URL 설정 지원 (IPv4 및 IPv6 동적 구성, 프로토콜에 따른 포트 기본값 자동 설정)

| -             | Example                                                     | Description                                |
|---------------|-------------------------------------------------------------|--------------------------------------------|
| IP            | `192.168.0.1`, `fd00::1`                                    | 특정 IPv4 또는 IPv6 주소 허용 (모든 포트)  |
| IP + Port     | `192.168.0.1:8080`, `[fd00::1]:8443`                        | 특정 IP의 특정 포트만 허용                 |
| CIDR          | `192.168.0.0/24`, `10.0.0.0/8`, `fd00::/64`                 | 서브넷 대역 전체 허용 (모든 포트)          |
| CIDR + Port   | `192.168.0.0/24:22`, `[fd00::/64]:8080`                     | 서브넷 대역의 특정 포트만 허용             |
| Domain        | `example.com`                                               | DNS 해석된 모든 IPv4/IPv6 허용 (모든 포트) |
| Domain + Port | `example.com:443`                                           | DNS 해석된 IP들의 특정 포트만 허용         |
| Port          | `*:8080`, `8080`                                            | 모든 IP에 대해 지정한 포트 허용            |
| URL           | `https://api.github.com/v1`, `http://192.168.1.1:8080/path` | URL에서 Domain과 Port를 추출하여 등록      |

- 도메인 및 URL의 경우 등록 시점에 조회된 IPv4 및 IPv6로 화이트리스트를 구성합니다.
- 데몬에서는 `refresh`를 통해 IP를 갱신할 수 있습니다.



## Usage

> [!TIP]
> [Releases](https://github.com/ransomguard/firewall-manager/releases)
> 페이지에서 실행 파일을 다운로드할 수 있습니다.

빌드 시 `r0-fw-cli.exe`와 `r0-fw-daemon.exe` 파일이 생성됩니다.

Usage: `file.exe [-d <both|out|in>] [target_1] [target_2] ...`

- `-d`, `--direction <both|out|in>`: 화이트리스트 허용 방향 설정 (기본값: `both`)

### CLI

파일 실행 시 전체 네트워크가 차단되며, 인자로 전달된 대상들을 화이트리스트로 설정합니다.
`Ctrl+c`를 눌러 종료할 때까지 대기하며, 종료 시 네트워크 차단을 해제합니다.

```powershell
r0-fw-cli.exe 192.168.0.1 [fd00::1/64]:8000 https://sub.example.com/path/to
r0-fw-cli.exe -d out 192.168.0.1:8080
r0-fw-cli.exe -d in 8080 *:8080
```

### Daemon

> [!NOTE]
> 기본적으로 네트워크 차단이 활성화되지 않습니다.

파일 실행 시 Named Pipe(`\\.\pipe\Ransom0_Firewall`) 기반 IPC 통신을 통해
네트워크 차단을 on/off하거나 Whitelist 룰을 설정할 수 있습니다.

Whitelist 구성 값은 데몬을 종료할 때까지 메모리에 저장되며 off 시에도 유지됩니다.
따라서 off 후에도 get/set/refresh 등의 기능을 이어서 사용할 수 있으며,
비활성화된 후 변경된 값은 on 시 Whitelist가 구성되지 않을 때 적용됩니다.

```powershell
r0-fw-daemon.exe
```

CLI처럼 초기 값을 구성할 수도 있습니다.
초기 값을 구성할 경우 차단이 기본적으로 활성화됩니다.

```powershell
r0-fw-daemon.exe 192.168.0.1 [fd00::1/64]:8000 https://sub.example.com/path/to
r0-fw-daemon.exe -d in 192.168.0.1:8080
```

#### on

> [!NOTE]
> 차단이 비활성화된 경우 활성화합니다.

Whitelist를 제공하지 않으면 저장된 구성을 그대로 적용합니다.

```jsonc
{"action":"on"}
```

제공된 값으로 Whitelist를 구성합니다.

`direction` ("both", "out", "in")을 지정할 수 있습니다.
(생략 시 기존 상태 유지)

```jsonc
{"action":"on","direction":"both","whitelist":["192.168.0.1"]}
```

#### set

> [!NOTE]
> 차단이 비활성화된 경우 자동으로 활성화하지 않습니다.

Whitelist를 설정합니다.
이전 구성 값은 전부 제거됩니다.

`direction` ("both", "out", "in")을 지정할 수 있습니다.
(생략 시 기존 상태 유지)

`whitelist` key가 없으면 `refresh`와 동일하게 동작합니다.

```jsonc
{"action":"set","direction":"both","whitelist":["192.168.0.1"]}
```

#### get

현재 구성된 Whitelist를 조회합니다.

```jsonc
{"action":"get"}
```

#### refresh

현재 구성된 Whitelist를 갱신합니다.
도메인에 연결된 IP를 갱신할 때 사용합니다.

```jsonc
{"action":"refresh"}
```

#### off

네트워크 차단을 해제합니다.

```jsonc
{"action":"off"}
```

#### Response

##### Response: Error

```jsonc
{
    "success": false,
    "action": "on", // set, refresh 등, 생략될 수 있음
    "message": "string"
}
```

##### Response: on/set/get/refresh

`whitelist` 값은 `WhitelistItem[]`으로 구성됩니다.
`WhitelistItem` 구조는 [아래 참고](#whitelistitem)

```jsonc
{
    "success": true,
    "active": true, // 네트워크 차단 활성화 상태 여부, on은 true로 고정
    "action": "on", // set, get, refresh
    "direction": "both", // "both", "outbound", "inbound"
    "whitelist": []
}
```

##### Response: off

```jsonc
{
    "success": true,
    "active": false, // 네트워크 차단 활성화 상태 여부, false로 고정
    "action": "off"
}
```

#### WhitelistItem

응답에 포함되는 Whitelist 아이템 구조입니다.

- `value` 값은 정규화를 거치지 않은 사용자 입력값입니다.
- `data.port`가 0인 경우 포트가 설정되지 않았음을 의미합니다.

##### IPv4

```jsonc
{
    "type": "ipv4",
    "value": "192.168.0.1",
    "data": {
        "ipv4": "192.168.0.1",
        "port": 0,
        "cidr": 32
    }
}
```

##### IPv6

```jsonc
{
    "type": "ipv6",
    "value": "[fd00::/64]:8000",
    "data": {
        "ipv6": "fd00::",
        "port": 8000,
        "cidr": 64
    }
}
```

##### Domain

```jsonc
{
    "type": "domain",
    "value": "example.com",
    "data": {
        "domain": "example.com",
        "port": 0,
        "ipv4": [
            "192.168.0.1"
        ],
        "ipv6": [
            "fd00::1"
        ]
    }
}
```

##### URL

```jsonc
{
    "type": "url",
    "value": "https://example.com/path/to",
    "data": {
        "domain": "example.com",
        "port": 443,
        "ipv4": [
            "192.168.0.1"
        ],
        "ipv6": [
            "fd00::1"
        ]
    }
}
```
