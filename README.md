# IP 차단 및 해제 도구

방화벽 룰은 다음과 같은 규칙 이름으로 관리됩니다.

- 인바운드: `Block_Malicious_IP_List_IN`
- 아웃바운드: `Block_Malicious_IP_List_OUT`



## 사용법

> [!NOTE]
> `output.exe`는 빌드 후 생성된 실행 파일

### 차단

```powershell
output.exe add 192.168.1.100
output.exe add 192.168.1.100 192.168.1.200
output.exe add 192.168.1.0/24
```

### 해제

```powershell
output.exe remove 192.168.1.100
output.exe remove 192.168.1.100 192.168.1.200
output.exe remove 192.168.1.0/24
```

### 차단된 IP 목록

```powershell
output.exe list
```

### 차단된 IP 모두 제거

```powershell
output.exe clear
```
