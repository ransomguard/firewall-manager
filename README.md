# Firewall Manager

> [!NOTE]
> Windows 전용이며, 방화벽 룰이 아닌
> `WFP(Windows Filtering Platform)`를 직접 제어합니다.

기본적으로 네트워크 전체를 차단합니다.
Whitelist를 통해 특정 IP와의 통신을 허용할 수 있습니다.



## 사용법

> [!NOTE]
> 빌드 시 `Ransom0_Firewall_CLI.exe`와 `Ransom0_Firewall_Daemon.exe` 파일이 생성됩니다.

도메인의 경우 등록 시점에 조회된 IPv4 및 IPv6로 화이트리스트를 구성합니다.
데몬에서는 `refresh`를 통해 IP를 갱신할 수 있습니다.

### CLI

파일 실행 시 전체 네트워크가 차단되며, 인자로 전달된 IP 및 도메인을 화이트리스트로 설정합니다.
`Ctrl+c`를 눌러 종료할 때까지 대기하며, 종료 시 네트워크 차단을 해제합니다.

Usage: `Ransom0_Firewall_CLI.exe [whitelist_ip_or_domain_1] [whitelist_ip_or_domain_2] ...`

```powershell
Ransom0_Firewall_CLI.exe 192.168.0.1 fd00::1 example.com
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
Ransom0_Firewall_Daemon.exe
```

CLI처럼 초기 값을 구성할 수도 있습니다.
초기 값을 구성할 경우 차단이 기본적으로 활성화됩니다.

```powershell
Ransom0_Firewall_Daemon.exe 192.168.0.1 fd00::1 example.com
```

#### on

> [!NOTE]
> 차단이 비활성화된 경우 활성화합니다.

Whitelist를 제공하지 않으면 저장된 구성을 그대로 적용합니다.
Whitelist를 구성하지 않으려면 그 다음 방식을 사용해야 합니다.

```jsonc
{"action":"on"}
```

제공된 값으로 Whitelist를 구성합니다.
빈 배열을 전달하여 Whitelist 구성 없이 활성화할 수 있습니다.

```jsonc
{"action":"on","whitelist":["192.168.0.1","fd00::1","example.com"]}
```

#### set

> [!NOTE]
> 차단이 비활성화된 경우 자동으로 활성화하지 않습니다.

Whitelist를 설정합니다.
이전 구성 값은 전부 제거됩니다.

`whitelist` key가 없으면 `refresh`와 동일하게 동작합니다.

```jsonc
{"action":"set","whitelist":["192.168.0.1","fd00::1","example.com"]}
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

#### 응답 구조

##### 에러 응답

```jsonc
{
    "success": false,
    "action": "on", // set, refresh 등, 생략될 수 있음
    "message": "string",
}
```

##### on/set/get/refresh 응답

`Whitelist` 값은 `WhitelistItem[]`으로 구성됩니다.
`WhitelistItem` 구조는 [아래 참고](#whitelistitem)

```jsonc
{
    "success": true,
    "active": true, // 네트워크 차단 활성화 상태 여부, on은 true로 고정
    "action": "on", // set, get, refresh
    "whitelist": [],
}
```

##### off 응답

```jsonc
{
    "success": true,
    "active": false, // 네트워크 차단 활성화 상태 여부, false로 고정
    "action": "off",
}
```

#### WhitelistItem

응답에 포함되는 Whitelist 아이템 구조입니다.

##### IPv4

```jsonc
{
    "type": "ipv4",
    "value": "192.168.0.1",
}
```

##### IPv6

```jsonc
{
    "type": "ipv6",
    "value": "fd00::1",
}
```

##### domain

```jsonc
{
    "type": "domain",
    "value": "example.com",
    "ipv4": [
        "192.168.0.1",
    ],
    "ipv6": [
        "fd00::1",
    ],
}
```
