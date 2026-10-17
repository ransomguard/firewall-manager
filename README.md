# IP 차단 및 해제 도구

방화벽 룰은 다음과 같은 규칙 이름으로 관리됩니다.

- 인바운드: `Block_Malicious_IP_List_IN`
- 아웃바운드: `Block_Malicious_IP_List_OUT`



## 사용법

각 파일별 용도와 사용법

### FirewallTool.cpp

> [!NOTE]
> `output.exe`는 빌드 후 생성된 실행 파일,
> block 대신 whitelist 입력 시 화이트리스트 등록, 해제 및 조회가 가능함

파일 실행 시 인자를 전달하여 룰을 업데이트함.
즉, 서버가 아닌 단발성 실행 파일임.

`output.exe <block|whitelist> <add|remove|list|clear> [IP1] [IP2] ...`

#### 차단

```powershell
output.exe block add 192.168.1.100
output.exe block add 192.168.1.100 192.168.1.200
output.exe block add 192.168.1.0/24
```

#### 해제

```powershell
output.exe block remove 192.168.1.100
output.exe block remove 192.168.1.100 192.168.1.200
output.exe block remove 192.168.1.0/24
```

#### 차단된 IP 목록

```powershell
output.exe block list
```

#### 차단된 IP 모두 제거

```powershell
output.exe block clear
```

### FirewallPipeServer.cpp

> [!NOTE]
> block 대신 whitelist 입력 시 화이트리스트 등록, 해제 및 조회가 가능함

실행 시 Named Pipe(`\\.\pipe\Ransom0Firewall`) 기반 IPC 통신을 통해 요청을 받고 방화벽 룰을 업데이트함.

#### 요청 구조

```jsonc
// 차단
{"target":"block","action":"add","ips":["192.168.1.100","10.0.0.0/24"]}

// 해제
{"target":"block","action":"remove","ips":["192.168.1.100","10.0.0.0/24"]}

// 목록
{"target":"block","action":"list"}
```

#### 응답 구조

`ips`는 add 및 remove 시에도 포함됨

```json
// 성공
{"success":true,"message":"string",ips:["192.168.1.100","10.0.0.0/24"]}

// 실패
{"success":false,"message":"string"}
```
