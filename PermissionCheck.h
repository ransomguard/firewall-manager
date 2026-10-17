#pragma once        // 중복 정의 에러 차단

#include <iostream>
#include <windows.h>

// 권한 검사를 위해 Advapi32 라이브러리 링크
#pragma comment(lib, "Advapi32.lib")

namespace Ransom0 {
    namespace Firewall {
        namespace Permission {
            // 방화벽 제어 권한(관리자 또는 네트워크 구성 연산자) 보유 여부를 확인하는 함수
            inline bool HasFirewallControl() {
                BOOL bIsAdmin = FALSE;
                BOOL bIsNetConfigOp = FALSE;

                SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
                PSID pAdminGroup = NULL;
                PSID pNetConfigGroup = NULL;

                // 1. 관리자 그룹 (Administrators: S-1-5-32-544) 체크
                if (AllocateAndInitializeSid(
                    &NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                    DOMAIN_ALIAS_RID_ADMINS,
                    0, 0, 0, 0, 0, 0, &pAdminGroup))
                {
                    CheckTokenMembership(NULL, pAdminGroup, &bIsAdmin);
                    FreeSid(pAdminGroup);
                }

                // 2. 네트워크 구성 연산자 그룹 (Network Configuration Operators: S-1-5-32-556) 체크
                if (AllocateAndInitializeSid(
                    &NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                    DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS,
                    0, 0, 0, 0, 0, 0, &pNetConfigGroup))
                {
                    CheckTokenMembership(NULL, pNetConfigGroup, &bIsNetConfigOp);
                    FreeSid(pNetConfigGroup);
                }

                // 둘 중 하나의 권한이라도 가지고 있다면 true 반환
                return (bIsAdmin == TRUE) || (bIsNetConfigOp == TRUE);
            }
        }
    }
}
