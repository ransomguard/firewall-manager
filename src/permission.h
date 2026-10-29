#pragma once



namespace Ransom0 {
    namespace Firewall {
        namespace Permission {
            /**
             * @brief 방화벽 제어 권한(관리자 또는 네트워크 구성 연산자) 보유 여부를 확인하는 함수
             * @return true: 권한 보유, false: 권한 없음
             */
            bool HasFirewallControl();
        }
    }
}
