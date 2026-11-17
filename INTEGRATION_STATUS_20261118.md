# RansomGuard 통합 호환 상태 — 2026-11-18

이전 PR #1의 데몬 구현이 main에 병합된 상태입니다. 이번 후속 업데이트에는 C++ 동작 변경이 없습니다.
Kernel v0.9.0, restore v0.5.0, UI 후속 IPC/상세 정보 변경과 함께 사용하는 배치 안내를 추가합니다.

- 데몬은 같은 VM의 `Ransom0_Firewall` 파이프로 요청을 받습니다.
- Python 대응 관리자와 Electron UI는 같은 SQLite hold DB를 사용해 대응/검토 중 정책 변경을 조정합니다.
- 미해결 검토/복구 실패 hold는 자동 해제하지 않습니다. UI의 상태 조회는 유지합니다.
- 이 데몬의 도메인/IP 허용 목록만으로 특정 프로그램의 특정 API 호출만 허용하는 정책이 완성되는 것은 아닙니다.
  JEV 브리지 실행 파일에 한정한 별도 Windows 정책은 배포 환경에서 검증해야 합니다.
- 시험 VM의 JEV-only 제한은 일반 설치에 자동 복제되지 않습니다. 통합 설정 도구는 네트워크를 변경하지 않습니다.

[통합 실행 및 빌드 안내](https://github.com/ransomguard/restore/blob/main/v0.5.0/deployment/README_KO.md)
에서 실행 파일 경로를 지정하면 데몬/UI/수집기를 같은 상태 DB와 연결합니다.
기존 데몬 CLI·화이트리스트·WFP 수명/방향 의미는 유지합니다.
