#include <windows.h>

#include "permission.h"

#pragma comment(lib, "Advapi32.lib")



namespace Ransom0 {
    namespace Firewall {
        namespace Permission {
            bool HasFirewallControl() {
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
