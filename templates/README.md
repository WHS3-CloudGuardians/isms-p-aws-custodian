# AWS 보안 점검 매트릭스 (Cloud Custodian 기반)

본 문서는 Cloud Custodian 정책을 기준으로, 각 리소스/정책의 위험도, 실행 모드, 조치 수준(알림만/자동조치)을 표로 정리하고
그 판단 기준을 명확히 설명한다.

## 1) 위험도 구분
| 위험도 | 내    용 | 조치기간 | 비고 |
|---|---|---|---|
| 상 | 관리자 계정/주요 정보 유출 등 **치명적 피해**로 직결 가능 | 단기 | 퍼블릭 접근, 권한승격 경로, MFA 미적용 등 |
| 중 | 노출된 정보를 통해 **추가 정보 유출/권한 확대** 우려 | 중기 | 암호화/버전닝/로깅 미적용, 구성 취약 등 |
| 하 | 타 취약점과 연계 가능한 **잠재적 위험** | 장기 | 하우스키핑/비용 중심 이슈 등 |

> 산정 방법: 외부노출성, 데이터/권한 민감도, 악용 용이성 지표로 평가.
정책 이름에 포함된 키워드(예: delete, public, unrestricted 등)나 어떤 리소스를 다루는지(S3, IAM, RDS 등)를 기준으로 위험도를 추정  

## 2) 핵심 기준 요약
- **CloudTrail**: 변경 **즉시 위험**(SG 공개 인바운드, launch‑wizard SG, PAB/ACL/Policy 변경 등) → **실시간 탐지**, 안전하면 **자동조치**
- **Periodic**: **상태 컴플라이언스/레거시 보완**(RDS 백업, EBS 스냅샷/암호화, S3 라이프사이클 등) → **전수 점검**
- **자동조치 + 알림**: `remove-`/`set-`/`delete` 등 **실질적 조치**일 때, Slack=`good`
- **알림만**: 운영 영향·합의 필요 또는 **비실질 액션**(`tag`/`mark-for-op`/`post-finding` 등) → Slack=`warning`/`danger`
- **색상 구분**: 정책이 실제로 자동조치(차단, 수정 등)까지 실행되면 결과 알림 색상은 `good`(🟢)으로 표시.
  반대로 알림만 하고 조치는 하지 않는 경우에는 위험 수준에 따라 `warning`(🟠) 또는 `danger`(🔴) 색상을 사용.

---

아래 표는 **영역별로 구분**하고, 각 행은 **번호(영역-순번)**로 식별합니다.  
열은 다음과 같습니다: **No. / 서비스 / 정책명 / 설명 / 리소스 / 권장 모드 / 권장 조치 / 알림색상 / 위험도 / 조치기간 / 트리거조건 / 템플릿 파일**

---

## 1. 감사/컴플라이언스

| No. | 서비스 | 정책명 | 설명 | 리소스 | 모드 | 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|-----|---|---|---|---|---|---|---|---|---|---|---|
| 1-01 | accessanalyzer | accessanalyzer_enabled | Access Analyzer가 계정에 활성화되어 있는지 점검 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 시 정책 조건 위반 | accessanalyzer.yaml.template |
| 1-02 | account | account_maintain_current_contact_details | 계정 연락처 정보가 최신인지 확인 | aws.org-account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 시 정책 조건 위반 | account.yaml.template |
| 1-03 | account | account_maintain_different_contact_details_to | 보안/청구/운영 연락처를 **분리**해 등록했는지 확인 | aws.org-account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 시 정책 조건 위반 | account.yaml.template |
| 1-04 | account | account_security_contact_information_is_registered | 보안(Security) 연락처가 등록되어 있는지 확인 | aws.org-account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 시 정책 조건 위반 | account.yaml.template |
| 1-05 | account | account_security_questions_are_registered_in_account | 계정 보안 질문/복구 정보가 구성되었는지 점검 | aws.org-account | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 정책 조건 위반 | account.yaml.template |
| 1-06 | cloudtrail | cloudtrail_bucket_requires_mfa_delete | CloudTrail 로그 S3 버킷에 MFA Delete 미적용 감지 | aws.s3 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 상태 위반: MFA 미적용 | cloudtrail.yaml.template |
| 1-07 | cloudtrail | cloudtrail_cloudwatch_logging_enabled | CloudTrail의 CloudWatch Logs 연동/로깅 미설정 자동 구성 | aws.cloudtrail | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-08 | cloudtrail | cloudtrail_insights_exist | CloudTrail Insights 비활성 감지 및 통보 | aws.cloudtrail | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-09 | cloudtrail | cloudtrail_kms_encryption_enabled | CloudTrail KMS 암호화 미적용 감지 | aws.cloudtrail | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 암호화 미적용 | cloudtrail.yaml.template |
| 1-10 | cloudtrail | cloudtrail_log_file_validation_enabled | 로그 무결성 검증(Log File Validation) 미적용 감지 | aws.cloudtrail | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-11 | cloudtrail | cloudtrail_logs_s3_bucket_access_logging_enabled | CloudTrail 로그 버킷 Access Logging 미설정 감지 | aws.s3 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-12 | cloudtrail | cloudtrail_logs_s3_bucket_is_not_publicly_accessible | CloudTrail 로그 버킷 퍼블릭 접근 감지 | aws.s3 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 퍼블릭 접근 | cloudtrail.yaml.template |
| 1-13 | cloudtrail | cloudtrail_multi_region_enabled | 멀티리전 Trail 미구성 감지 | aws.cloudtrail | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-14 | cloudtrail | cloudtrail_multi_region_or_no_management_events | 멀티리전/Management Events 미수집 감지 | aws.cloudtrail | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-15 | cloudtrail | cloudtrail_s3_dataevents_read_enabled | S3 Read Data Events 미수집 감지 | aws.cloudtrail | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-16 | cloudtrail | cloudtrail_s3_dataevents_write_enabled | S3 Write Data Events 미수집 감지 | aws.cloudtrail | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 시 로깅/모니터링 미설정 | cloudtrail.yaml.template |
| 1-17 | config | config_recorder_all_regions_enabled | AWS Config 레코더가 모든 리전에서 활성/전송되는지 점검 | aws.config-recorder | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 시 정책 조건 위반 | config.yaml.template |
| 1-18 | organization | organizations_scp_check_deny_regions | 미사용 리전 차단용 SCP 구성 여부 점검 및 자동 조치 | aws.org-account | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검 시 정책 조건 위반 | organization.yaml.template |
| 1-19 | organization | organizations_tags_policies_enabled_and_attached | Tag Policies 활성/연결 여부 점검 및 자동 조치 | aws.org-account | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검 시 정책 조건 위반 | organization.yaml.template |
| 1-20 | securityhub | securityhub_enabled | Security Hub 비활성 계정 감지 | aws.account | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 시 정책 조건 위반 | securityhub.yaml.template |

---

## 2. 권한 관리

| No. | 서비스 | 정책명 | 설명 | 리소스 | 권장 모드 | 권장 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2-01 | iam | iam_administrator_access_with_mfa | AdminAccess 보유 사용자 중 MFA 미적용 탐지 | aws.iam-user | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: MFA 미적용 | iam.yaml.template |
| 2-02 | iam | iam_avoid_root_usage | Root 계정 사용 이벤트 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: Root 사용 흔적 | iam.yaml.template |
| 2-03 | iam | iam_aws_attached_policy_no_administrative_privileges | AWS 관리형 AdminAccess 부여 사용자 탐지 | aws.iam-user | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-04 | iam | iam_check_saml_providers_sts | SAML Provider ARN에 sts.amazonaws.com 누락 탐지 | aws.iam-saml-provider | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: Federation 설정 오류 | iam.yaml.template |
| 2-05 | iam | iam_customer_attached_policy_no_adminis | 고객관리형 정책에 '*:*' 허용 감지 (부착됨) | aws.iam-policy | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-06 | iam | iam_customer_unattached_policy_no_adminis | 고객관리형 정책에 '*:*' 허용 감지 (미부착) | aws.iam-policy | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-07 | iam | iam_group_administrator_access_policy | AdminAccess 부여 그룹 탐지 | aws.iam-group | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-08 | iam | iam_inline_policy_allows_privilege_escalation | 인라인 정책으로 권한승격 가능 경로 탐지 (iam:PassRole 등) | aws.iam-user | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-09 | iam | iam_inline_policy_no_administrative_privileges | 인라인 정책에 '*:*' 허용 탐지 | aws.iam-user | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-10 | iam | iam_inline_policy_no_full_access_to_cloudtrail | 인라인 정책에 cloudtrail:* 전체권한 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-11 | iam | iam_inline_policy_no_full_access_to_kms | 인라인 정책에 kms:* 전체권한 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 과도 권한/암호화 위험 | iam.yaml.template |
| 2-12 | iam | iam_no_custom_policy_permissive_role_assumption | sts:AssumeRole 전체 허용 커스텀 정책 탐지 | aws.iam-policy | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 Role Assume | iam.yaml.template |
| 2-13 | iam | iam_no_root_access_key | Root 액세스키 존재/활성 탐지 | aws.account | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: Root 키 존재 | iam.yaml.template |
| 2-14 | iam | iam_password_policy_expires_90_days_or_less | 비밀번호 만료가 90일 이하로 설정되지 않음 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 비밀번호 정책 | iam.yaml.template |
| 2-15 | iam | iam_password_policy_lowercase | 소문자 요구 미설정 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 비밀번호 정책 | iam.yaml.template |
| 2-16 | iam | iam_password_policy_minimum_length_14 | 최소 길이 14 미만 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 비밀번호 정책 | iam.yaml.template |
| 2-17 | iam | iam_password_policy_number | 숫자 요구 미설정 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 비밀번호 정책 | iam.yaml.template |
| 2-18 | iam | iam_password_policy_reuse_24 | 최근 24개 재사용 금지 미설정 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 비밀번호 정책 | iam.yaml.template |
| 2-19 | iam | iam_password_policy_symbol | 특수문자 요구 미설정 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 비밀번호 정책 | iam.yaml.template |
| 2-20 | iam | iam_password_policy_uppercase | 대문자 요구 미설정 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 비밀번호 정책 | iam.yaml.template |
| 2-21 | iam | iam_policy_allows_privilege_escalation | iam:PassRole 등 권한승격 경로 포함 정책 탐지 | aws.iam-policy | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-22 | iam | iam_policy_attached_only_to_group_or_roles | 정책이 사용자/그룹에 직접 부착된 경우 탐지 | aws.iam-policy | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 부착 위치 점검 | iam.yaml.template |
| 2-23 | iam | iam_policy_no_full_access_to_cloudtrail | CloudTrail 전체 권한 정책 탐지 | aws.iam-policy | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-24 | iam | iam_policy_no_full_access_to_kms | KMS 전체 권한 정책 탐지 | aws.iam-policy | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 암호화 위험 | iam.yaml.template |
| 2-25 | iam | iam_role_cross_service_confused_deputy_prevention | 신뢰 정책에 StringEquals 조건 누락(혼동 대리) 탐지 | aws.iam-role | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 신뢰정책 취약 | iam.yaml.template |
| 2-26 | iam | iam_root_hardware_mfa_enabled | Root 하드웨어 MFA 미적용 탐지 | aws.account | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: MFA 미적용 | iam.yaml.template |
| 2-27 | iam | iam_root_mfa_enabled | Root MFA 미적용 탐지 | aws.account | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: MFA 미적용 | iam.yaml.template |
| 2-28 | iam | iam_rotate_access_key_90_days | 90일 이상 미회전 액세스키 사용자 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 키 로테이션 | iam.yaml.template |
| 2-29 | iam | iam_securityaudit_role_created | SecurityAudit 역할 부재 탐지(필요 시 생성) | aws.iam-role | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 역할 부재 | iam.yaml.template |
| 2-30 | iam | iam_support_role_created | Support 역할 부재 탐지(필요 시 생성) | aws.iam-role | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 역할 부재 | iam.yaml.template |
| 2-31 | iam | iam_user_accesskey_unused | 90일 이상 미사용 액세스키 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 키 미사용 | iam.yaml.template |
| 2-32 | iam | iam_user_administrator_access_policy | AdminAccess 정책 부여 사용자 탐지 | aws.iam-user | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 과도 권한 | iam.yaml.template |
| 2-33 | iam | iam_user_console_access_unused | 콘솔 전용 사용자(Access Key 사용 없음) 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 계정 정리 | iam.yaml.template |
| 2-34 | iam | iam_user_hardware_mfa_enabled | 하드웨어 MFA 미적용 사용자 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: MFA 미적용 | iam.yaml.template |
| 2-35 | iam | iam_user_mfa_enabled_console_access | 콘솔 접근 + MFA 미적용 사용자 탐지 | aws.iam-user | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: MFA 미적용 | iam.yaml.template |
| 2-36 | iam | iam_user_no_setup_initial_access_key | 초기 액세스키 보존 사용자 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 키 정리 | iam.yaml.template |
| 2-37 | iam | iam_user_two_active_access_key | 동시 활성 액세스키 2개 이상 사용자 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 키 정책 | iam.yaml.template |
| 2-38 | iam | iam_user_with_temporary_credentials | STS 임시 자격 보유 사용자 탐지 | aws.iam-user | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 임시자격 사용 | iam.yaml.template |
| 2-39 | kms | kms_cmk_are_used | Customer managed KMS 키가 실제 사용 중인지 점검 | aws.kms-key | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 미사용 키 | kms.yaml.template |
| 2-40 | kms | kms_cmk_not_deleted_unintentionally | KMS 키 오삭제 방지 설정 점검(삭제보호/보존) | aws.kms-key | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 삭제 보호 | kms.yaml.template |
| 2-41 | kms | kms_cmk_rotation_enabled | KMS 키 자동 로테이션 미설정 감지(필요 시 설정) | aws.kms-key | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검: 로테이션 | kms.yaml.template |
| 2-42 | kms | kms_key_not_publicly_accessible | KMS 키 퍼블릭 접근 가능 구성 탐지 | aws.kms-key | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭 접근 | kms.yaml.template |

---

## 3. 네트워크/엣지

| No. | 서비스 | 정책명 | 설명 | 리소스 | 권장 모드 | 권장 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 3-01 | apigateway | apigateway_restapi_client_certificate_enabled | API Gateway 클라이언트 인증서/검증 미적용 탐지 | aws.rest-api | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: TLS/인증서 미설정 | apigateway.yaml.template |
| 3-02 | apigateway | apigateway_restapi_logging_enabled | API Gateway 액세스/실행 로그 미설정 탐지 | aws.rest-api | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 로깅 미설정 | apigateway.yaml.template |
| 3-03 | apigateway | apigateway_restapi_public | API Gateway 엔드포인트 퍼블릭 노출 탐지 | aws.rest-api | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭 접근 | apigateway.yaml.template |
| 3-04 | cloudfront | cloudfront_distributions_field_level_encrypt_enabled | 필드 레벨 암호화 미설정 배포 탐지 | aws.distribution | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | cloudfront.yaml.template |
| 3-05 | cloudfront | cloudfront_distributions_geo_restrictions_enabled | 지리적 제한(Geo Restriction) 미설정 탐지 | aws.distribution | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 정책 미설정 | cloudfront.yaml.template |
| 3-06 | cloudfront | cloudfront_distributions_https_enabled | HTTPS 미사용 배포 탐지 | aws.distribution | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: TLS 미설정 | cloudfront.yaml.template |
| 3-07 | cloudfront | cloudfront_distributions_logging_enabled | 액세스 로깅 미설정 배포 탐지 | aws.distribution | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 로깅 미설정 | cloudfront.yaml.template |
| 3-08 | cloudfront | cloudfront_distributions_using_deprecated_ssl_protocol | 폐기된 SSL 정책 사용 탐지 | aws.distribution | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: TLS 약함 | cloudfront.yaml.template |
| 3-09 | cloudfront | cloudfront_distributions_using_waf | WAF/Web ACL 미연동 배포 탐지 | aws.distribution | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: WAF 미연동 | cloudfront.yaml.template |
| 3-10 | elb | elbv2_deletion_protection | ALB 삭제보호 미설정 생성/수정 이벤트 감지 | aws.app-elb | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | CreateLoadBalancer | elb.yaml.template |
| 3-11 | elb | elbv2_desync_mitigation_mode | ALB Desync 방어 모드 미적용 생성/수정 이벤트 | aws.app-elb | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | CreateLoadBalancer, ModifyLoadBalancerAttributes | elb.yaml.template |
| 3-12 | elb | elbv2_insecure_listeners | TLS/HTTPS 미사용 리스너 탐지 | aws.app-elb | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: TLS 미설정 | elb.yaml.template |
| 3-13 | elb | elbv2_insecure_ssl_ciphers | 폐기된 SSL 정책 사용 리스너 탐지 | aws.app-elb | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: TLS 약함 | elb.yaml.template |
| 3-14 | elb | elbv2_internet_facing | 인터넷 페이싱 ALB 검출(리뷰 대상) | aws.app-elb | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭 노출 | elb.yaml.template |
| 3-15 | elb | elbv2_is_in_multiple_az | 다중 AZ 배포 미구성 생성 이벤트 감지 | aws.app-elb | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | CreateLoadBalancer | elb.yaml.template |
| 3-16 | elb | elbv2_listeners_underneath | 리스너 미부착 ALB 탐지 | aws.app-elb | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 리스너 없음 | elb.yaml.template |
| 3-17 | elb | elbv2_logging_enabled | ALB 액세스 로깅 미설정 탐지 | aws.app-elb | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 로깅 미설정 | elb.yaml.template |
| 3-18 | elb | elbv2_waf_acl_attached | ALB에 WAF(Web ACL) 미부착 탐지 | aws.app-elb | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: WAF 미연동 | elb.yaml.template |
| 3-19 | networkfirewall | networkfirewall_in_all_vpc | 모든 VPC에 Network Firewall 미배포 탐지 | aws.vpc | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 방화벽 미배포 | networkfirewall.yaml.template |
| 3-20 | route53 | route53_public_hosted_zones_cloudwatch_logging_enabled | 퍼블릭 호스티드 존 쿼리 로깅 미설정 탐지 | aws.hostedzone | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭/로깅 미설정 | route53.yaml.template |
| 3-21 | vpc | vpc-subnet-disable-default-public-ip | Subnet의 기본 퍼블릭 IP 자동할당 비활성 점검 | aws.subnet | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭 자동할당 | vpc.yaml.template |
| 3-22 | vpc | vpc_different_regions | 단일 리전에 VPC 1개만 존재 시 알림 | aws.vpc | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 리전/망 구성 취약 | vpc.yaml.template |
| 3-23 | vpc | vpc_flow_logs_enabled | VPC Flow Logs 미설정 탐지 | aws.vpc | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 로깅 미설정 | vpc.yaml.template |
| 3-24 | vpc | vpc_subnet_different_az | 서브넷이 단일 AZ에만 존재 탐지 | aws.vpc | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 가용성 취약 | vpc.yaml.template |
| 3-25 | vpc | vpc_subnet_separate_private_public | 프라이빗 서브넷 없이 퍼블릭만 존재 탐지 | aws.vpc | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭 노출 | vpc.yaml.template |

---

## 4. 컴퓨트

| No. | 서비스 | 정책명 | 설명 | 리소스 | 권장 모드 | 권장 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 4-01 | ec2 | ec2_ebs_default_encryption | 계정 기본 EBS 암호화 비활성 설정 이벤트 감지 | aws.account | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | DisableEbsEncryptionByDefault | ec2_ebs.yaml.template |
| 4-02 | ec2 | ec2_ebs_default_encryption | 계정 기본 EBS 암호화 비활성 설정 이벤트 감지 | aws.account | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | DisableEbsEncryptionByDefault | ec2.yaml.template |
| 4-03 | ec2 | ec2_ebs_snapshots_encrypted | 암호화되지 않은 EBS 스냅샷 탐지 | aws.ebs-snapshot | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | ec2_ebs.yaml.template |
| 4-04 | ec2 | ec2_ebs_snapshots_encrypted | 암호화되지 않은 EBS 스냅샷 탐지 | aws.ebs-snapshot | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | ec2.yaml.template |
| 4-05 | ec2 | ec2_ebs_volume_encryption | 암호화되지 않은 EBS 볼륨 탐지(스냅샷 생성 포함) | aws.ebs | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | ec2_ebs.yaml.template |
| 4-06 | ec2 | ec2_ebs_volume_encryption | 암호화되지 않은 EBS 볼륨 탐지(스냅샷 생성 포함) | aws.ebs | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | ec2.yaml.template |
| 4-07 | ec2 | ec2_ebs_volume_snapshots_exists | 스냅샷이 없는 EBS 볼륨에 대해 스냅샷 생성/태깅 | aws.ebs | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 백업 미구성 | ec2_ebs.yaml.template |
| 4-08 | ec2 | ec2_ebs_volume_snapshots_exists | 스냅샷이 없는 EBS 볼륨에 대해 스냅샷 생성/태깅 | aws.ebs | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 백업 미구성 | ec2.yaml.template |
| 4-09 | ec2 | ec2_elastic_ip_unassigned | 미할당 Elastic IP 탐지(비용/보안 관점) | aws.elastic-ip | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | ec2_others.yaml.template |
| 4-10 | ec2 | ec2_elastic_ip_unassigned | 미할당 Elastic IP 탐지(비용/보안 관점) | aws.elastic-ip | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | ec2.yaml.template |
| 4-11 | ec2 | ec2_instance_account_imdsv2_enabled | 계정 차원의 IMDSv2 강제 설정 점검 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: IMDSv2 미강제 | ec2.yaml.template |
| 4-12 | ec2 | ec2_instance_account_imdsv2_enabled | 계정 차원의 IMDSv2 강제 설정 점검 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: IMDSv2 미강제 | ec2_instance.yaml.template |
| 4-13 | ec2 | ec2_instance_detailed_monitoring_enabled | EC2 상세 모니터링 비활성 → 자동 활성화 | aws.ec2 | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검: 모니터링 미설정 | ec2.yaml.template |
| 4-14 | ec2 | ec2_instance_detailed_monitoring_enabled | EC2 상세 모니터링 비활성 → 자동 활성화 | aws.ec2 | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검: 모니터링 미설정 | ec2_instance.yaml.template |
| 4-15 | ec2 | ec2_instance_imdsv2_enabled | 새 인스턴스 생성 시 IMDSv2 비활성 → 자동 활성화 | aws.ec2 | cloudtrail | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | RunInstances | ec2.yaml.template |
| 4-16 | ec2 | ec2_instance_imdsv2_enabled | 새 인스턴스 생성 시 IMDSv2 비활성 → 자동 활성화 | aws.ec2 | cloudtrail | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | RunInstances | ec2_instance.yaml.template |
| 4-17 | ec2 | ec2_instance_internet_facing_with_instance_profile | 퍼블릭 IP 보유 인스턴스의 IAM 프로파일 점검 | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭 노출 | ec2.yaml.template |
| 4-18 | ec2 | ec2_instance_internet_facing_with_instance_profile | 퍼블릭 IP 보유 인스턴스의 IAM 프로파일 점검 | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭 노출 | ec2_instance.yaml.template |
| 4-19 | ec2 | ec2_instance_managed_by_ssm | SSM 관리 미적용 인스턴스 탐지 | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: SSM 미적용 | ec2.yaml.template |
| 4-20 | ec2 | ec2_instance_managed_by_ssm | SSM 관리 미적용 인스턴스 탐지 | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: SSM 미적용 | ec2_instance.yaml.template |
| 4-21 | ec2 | ec2_instance_older_than_specific_days | 특정 일수 초과 구동 인스턴스 탐지 | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | ec2.yaml.template |
| 4-22 | ec2 | ec2_instance_older_than_specific_days | 특정 일수 초과 구동 인스턴스 탐지 | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | ec2_instance.yaml.template |
| 4-23 | ec2 | ec2_instance_port | 보안그룹/인스턴스 금지 포트 노출 점검 | aws.ec2 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 포트 노출 | ec2.yaml.template |
| 4-24 | ec2 | ec2_instance_port | 보안그룹/인스턴스 금지 포트 노출 점검 | aws.ec2 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 포트 노출 | ec2_instance.yaml.template |
| 4-25 | ec2 | ec2_instance_profile_attached | 인스턴스 프로파일 미연결 인스턴스 생성 이벤트 | aws.ec2 | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | RunInstances | ec2.yaml.template |
| 4-26 | ec2 | ec2_instance_profile_attached | 인스턴스 프로파일 미연결 인스턴스 생성 이벤트 | aws.ec2 | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | RunInstances | ec2_instance.yaml.template |
| 4-27 | ec2 | ec2_instance_public_ip | 퍼블릭 IP 인스턴스 탐지/태깅(필요 시 정지) | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭 노출 | ec2.yaml.template |
| 4-28 | ec2 | ec2_instance_public_ip | 퍼블릭 IP 인스턴스 탐지/태깅(필요 시 정지) | aws.ec2 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭 노출 | ec2_instance.yaml.template |
| 4-29 | ec2 | ec2_instance_secrets_user_data | UserData 내 하드코드 시크릿 탐지 | aws.ec2 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 시크릿 노출 | ec2.yaml.template |
| 4-30 | ec2 | ec2_instance_secrets_user_data | UserData 내 하드코드 시크릿 탐지 | aws.ec2 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 시크릿 노출 | ec2_instance.yaml.template |
| 4-31 | ec2 | ec2_launch_template_no_secrets | 시작 템플릿 UserData 내 시크릿 포함 탐지/태깅 | aws.launch-template-version | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 시크릿 노출 | ec2_others.yaml.template |
| 4-32 | ec2 | ec2_launch_template_no_secrets | 시작 템플릿 UserData 내 시크릿 포함 탐지/태깅 | aws.launch-template-version | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 시크릿 노출 | ec2.yaml.template |
| 4-33 | ec2 | ec2_networkacl_allow_ingress_any_port | NACL Ingress 0.0.0.0/0 전체포트 허용 탐지 | aws.network-acl | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: NACL 과다허용 | ec2_others.yaml.template |
| 4-34 | ec2 | ec2_networkacl_allow_ingress_any_port | NACL Ingress 0.0.0.0/0 전체포트 허용 탐지 | aws.network-acl | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: NACL 과다허용 | ec2.yaml.template |
| 4-35 | ec2 | ec2_networkacl_allow_ingress_tcp_port_22 | NACL Ingress 0.0.0.0/0 : 22 허용 탐지 | aws.network-acl | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: NACL 과다허용 | ec2_others.yaml.template |
| 4-36 | ec2 | ec2_networkacl_allow_ingress_tcp_port_22 | NACL Ingress 0.0.0.0/0 : 22 허용 탐지 | aws.network-acl | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: NACL 과다허용 | ec2.yaml.template |
| 4-37 | ec2 | ec2_networkacl_allow_ingress_tcp_port_3389 | NACL Ingress 0.0.0.0/0 : 3389 허용 탐지 | aws.network-acl | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: NACL 과다허용 | ec2_others.yaml.template |
| 4-38 | ec2 | ec2_networkacl_allow_ingress_tcp_port_3389 | NACL Ingress 0.0.0.0/0 : 3389 허용 탐지 | aws.network-acl | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: NACL 과다허용 | ec2.yaml.template |
| 4-39 | ec2 | ec2_securitygroup_allow | SG 인바운드 과다허용(예: 0.0.0.0/0) 추가 즉시 차단 | aws.security-group | cloudtrail | auto+notify | 🟢 조치완료 (good) | 상 | 단기 | AuthorizeSecurityGroupIngress | ec2_securitygroup.yaml.template |
| 4-40 | ec2 | ec2_securitygroup_allow | SG 인바운드 과다허용(예: 0.0.0.0/0) 추가 즉시 차단 | aws.security-group | cloudtrail | auto+notify | 🟢 조치완료 (good) | 상 | 단기 | AuthorizeSecurityGroupIngress | ec2.yaml.template |
| 4-41 | ec2 | ec2_securitygroup_default_restrict_traffic | default SG 과다허용 규칙 감지 | aws.security-group | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2_securitygroup.yaml.template |
| 4-42 | ec2 | ec2_securitygroup_default_restrict_traffic | default SG 과다허용 규칙 감지 | aws.security-group | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2.yaml.template |
| 4-43 | ec2 | ec2_securitygroup_from_launch_wizard | launch-wizard SG 생성 즉시 차단/정리 | aws.security-group | cloudtrail | auto+notify | 🟢 조치완료 (good) | 상 | 단기 | CreateSecurityGroup | ec2_securitygroup.yaml.template |
| 4-44 | ec2 | ec2_securitygroup_from_launch_wizard | launch-wizard SG 생성 즉시 차단/정리 | aws.security-group | cloudtrail | auto+notify | 🟢 조치완료 (good) | 상 | 단기 | CreateSecurityGroup | ec2.yaml.template |
| 4-45 | ec2 | ec2_securitygroup_not_used | 미사용 SG 월 1회 일괄 통보(오남용 방지) | aws.security-group | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | ec2_securitygroup.yaml.template |
| 4-46 | ec2 | ec2_securitygroup_not_used | 미사용 SG 월 1회 일괄 통보(오남용 방지) | aws.security-group | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | ec2.yaml.template |
| 4-47 | ec2 | ec2_securitygroup_with_many_ingress_egress_rules | 규칙 과다 SG 변경 이벤트 통보 | aws.security-group | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2_securitygroup.yaml.template |
| 4-48 | ec2 | ec2_securitygroup_with_many_ingress_egress_rules | 규칙 과다 SG 변경 이벤트 통보 | aws.security-group | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2.yaml.template |
| 4-49 | lambda | awslambda-function-inside-vpc | VPC 외부 Lambda 함수 탐지 | aws.lambda | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | lambda.yaml.template |
| 4-50 | lambda | awslambda-function-no-secrets-in-variables | Lambda 환경변수 내 시크릿 포함 탐지 | aws.lambda | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 시크릿 노출 | lambda.yaml.template |
| 4-51 | lambda | awslambda-function-not-publicly-accessible | 퍼블릭 접근 가능한 Lambda 탐지 | aws.lambda | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭 노출 | lambda.yaml.template |
| 4-52 | lambda | awslambda-function-using-supported-runtimes | 지원 종료/미지원 런타임 사용 함수 탐지 | aws.lambda | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 런타임 노후 | lambda.yaml.template |
| 4-53 | lambda | awslambda_function_inside_vpc | Lambda의 VPC 연결 구성 점검 | aws.lambda | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | lambda.yaml.template |
| 4-54 | lambda | lambda-cloudtrail-logging-enabled | Lambda 호출 로그 미수집(CloudTrail) 탐지 | aws.cloudtrail | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 로깅 미설정 | lambda.yaml.template |
| 4-55 | lambda | lambda_func_cloudtrail_log_enabled | Lambda 로그 통합(CloudWatch/CloudTrail) 미설정 탐지 | aws.lambda | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 로깅 미설정 | lambda.yaml.template |

---

## 5. 데이터 보호

| No. | 서비스 | 정책명 | 설명 | 리소스 | 권장 모드 | 권장 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 5-01 | athena | athena_workgroup_encryption | Athena Workgroup 결과 암호화 미설정 탐지 | aws.athena-work-group | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 암호화 미적용 | athena.yaml.template |
| 5-02 | athena | athena_workgroup_enforce_configuration | Workgroup 구성(쿼리 결과 위치/암호화 등) 미강제 탐지 | aws.athena-work-group | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | athena.yaml.template |
| 5-03 | dynamodb | dynamodb_tables_kms_cmk_encryption_enabled | DynamoDB KMS CMK 암호화 미적용 탐지 | aws.dynamodb-table | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 암호화 미적용 | dynamodb.yaml.template |
| 5-04 | dynamodb | dynamodb_tables_pitr_enabled | DynamoDB PITR(지속 백업) 미설정 탐지 | aws.dynamodb-table | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 백업 미구성 | dynamodb.yaml.template |
| 5-05 | efs | efs_encryption_at_rest_enabled | EFS 저장 데이터 암호화 미적용 탐지 | aws.efs | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | efs.yaml.template |
| 5-06 | efs | efs_have_backup_enabled | EFS 백업 미구성 탐지 | aws.efs | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 백업 미구성 | efs.yaml.template |
| 5-07 | efs | efs_not_publicly_accessible | EFS가 퍼블릭으로 노출되었는지 탐지 | aws.security-group | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭 노출 | efs.yaml.template |
| 5-08 | elasticache | elasticache_cluster_uses_public_subnet | 퍼블릭 서브넷에 배치된 클러스터 생성/수정 이벤트 | aws.cache-subnet-group | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | Create/ModifyReplicationGroup | elasticache.yaml.template |
| 5-09 | elasticache | elasticache_redis_cluster_auto_minor_version_upgrades | 자동 마이너 버전 업그레이드 미설정 이벤트 | aws.elasticache-group | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | Create/ModifyReplicationGroup | elasticache.yaml.template |
| 5-10 | elasticache | elasticache_redis_cluster_backup_enabled | 백업 미설정 이벤트 | aws.elasticache-group | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | Create/ModifyReplicationGroup | elasticache.yaml.template |
| 5-11 | elasticache | elasticache_redis_cluster_in_transit_encrypt_enabled | 전송구간 암호화 미설정 이벤트 | aws.elasticache-group | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | Create/ModifyReplicationGroup | elasticache.yaml.template |
| 5-12 | elasticache | elasticache_redis_cluster_multi_az_enabled | Multi-AZ 미설정 이벤트 | aws.elasticache-group | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | Create/ModifyReplicationGroup | elasticache.yaml.template |
| 5-13 | elasticache | elasticache_redis_cluster_rest_encryption_enabled | 저장 데이터 암호화 미설정 이벤트 | aws.elasticache-group | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | Create/ModifyReplicationGroup | elasticache.yaml.template |
| 5-14 | emr | emr_cluster_account_public_block_enabled | 계정 퍼블릭 블록 미설정 EMR 탐지 | aws.emr | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭 노출 | emr.yaml.template |
| 5-15 | glue | glue_etl_jobs_amazon_s3_encryption_enabled | Glue 보안구성의 S3 암호화 미적용 탐지 | aws.glue-security-configuration | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | glue.yaml.template |
| 5-16 | glue | glue_etl_jobs_cloudwatch_logs_encryption_enabled | Glue 로그 암호화/연동 미설정 탐지 | aws.glue-security-configuration | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 로깅/암호화 미설정 | glue.yaml.template |
| 5-17 | glue | glue_etl_jobs_job_bookmark_encryption_enabled | Glue Job Bookmark 암호화 미적용 탐지 | aws.glue-security-configuration | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 암호화 미적용 | glue.yaml.template |
| 5-18 | rds | rds_instance_backup_enabled | RDS 자동 백업 미설정 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 백업 미구성 | rds.yaml.template |
| 5-19 | rds | rds_instance_certificate_expiration | RDS 인증서 만료 임박 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: TLS/인증서 | rds.yaml.template |
| 5-20 | rds | rds_instance_copy_tags_to_snapshots | Snapshot 태그 복사 미설정 → 자동 설정 | aws.rds | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-21 | rds | rds_instance_default_admin | 기본 관리자 계정 사용 여부 점검 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-22 | rds | rds_instance_deletion_protection | 삭제 보호 미설정 인스턴스 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-23 | rds | rds_instance_deprecated_engine_version | 지원 종료/구버전 엔진 사용 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-24 | rds | rds_instance_enhanced_monitoring_enabled | Enhanced Monitoring 미설정 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-25 | rds | rds_instance_event_subscription_security_groups | 보안그룹 기반 이벤트 구독 미설정 탐지 | aws.rds-subscription | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-26 | rds | rds_instance_iam_authentication_enabled | IAM 인증 미적용 인스턴스 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-27 | rds | rds_instance_integration_cloudwatch_logs | CloudWatch Logs 미연동 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 로깅 미설정 | rds.yaml.template |
| 5-28 | rds | rds_instance_minor_version_upgrade_enabled | 자동 마이너 버전 업그레이드 미설정 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | rds.yaml.template |
| 5-29 | rds | rds_instance_multi_az | Multi-AZ 미구성 인스턴스 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 가용성 | rds.yaml.template |
| 5-30 | rds | rds_instance_no_public_access | 퍼블릭 접근 허용 RDS 탐지 | aws.rds | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭 노출 | rds.yaml.template |
| 5-31 | rds | rds_instance_storage_encrypted | 저장 데이터 암호화 미적용 RDS 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 암호화 미적용 | rds.yaml.template |
| 5-32 | rds | rds_instance_transport_encrypted | 전송구간 암호화 미적용 RDS 탐지 | aws.rds | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 암호화 미적용 | rds.yaml.template |
| 5-33 | rds | rds_snapshots_encrypted | 암호화되지 않은 RDS 스냅샷 탐지 | aws.rds-snapshot | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 암호화 미적용 | rds.yaml.template |
| 5-34 | rds | rds_snapshots_public_access | 퍼블릭 접근 가능한 RDS 스냅샷 자동 차단 | aws.rds-snapshot | periodic | auto+notify | 🟢 조치완료 (good) | 상 | 단기 | 주기 점검: 퍼블릭 노출 | rds.yaml.template |
| 5-35 | redshift | redshift_cluster_audit_logging | 감사 로깅 미설정 Redshift 탐지 | aws.redshift | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 로깅 미설정 | redshift.yaml.template |
| 5-36 | s3 | s3_account_level_public_access_blocks | 계정 차원의 PAB 미설정 탐지 | aws.account | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭 접근 | s3.yaml.template |
| 5-37 | s3 | s3_bucket_acl_prohibited | ACL 사용 버킷 탐지(차단 정책 권고) | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: ACL 정책 | s3.yaml.template |
| 5-38 | s3 | s3_bucket_cross_region_replication | CRR 미구성 버킷 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | s3.yaml.template |
| 5-39 | s3 | s3_bucket_default_encryption | 기본 암호화 미적용 버킷 자동 설정 | aws.s3 | periodic | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | 주기 점검: 암호화 미적용 | s3.yaml.template |
| 5-40 | s3 | s3_bucket_kms_encryption | KMS 기반 암호화 미적용 버킷 탐지 | aws.s3 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | s3.yaml.template |
| 5-41 | s3 | s3_bucket_level_public_access_block | PAB 변경 실시간 감지 | aws.s3 | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | DeleteBucketPublicAccessBlock, PutBucketPublicAccessBlock | s3.yaml.template |
| 5-42 | s3 | s3_bucket_lifecycle_enabled | Lifecycle 미구성 버킷 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 라이프사이클 | s3.yaml.template |
| 5-43 | s3 | s3_bucket_no_mfa_delete | MFA Delete 미적용 버킷 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: MFA 미적용 | s3.yaml.template |
| 5-44 | s3 | s3_bucket_object_lock | Object Lock 미적용 버킷 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 버전/보존 미적용 | s3.yaml.template |
| 5-45 | s3 | s3_bucket_object_versioning | 버전관리 미적용 버킷 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 버전 미적용 | s3.yaml.template |
| 5-46 | s3 | s3_bucket_policy_public_write_access | 버킷 정책 퍼블릭 쓰기 변경 실시간 감지 | aws.s3 | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | PutBucketPolicy | s3.yaml.template |
| 5-47 | s3 | s3_bucket_public_access | 버킷 퍼블릭 액세스 실시간 감지 | aws.s3 | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | PutBucketAcl, PutBucketPolicy | s3.yaml.template |
| 5-48 | s3 | s3_bucket_public_list_acl | Public-List ACL 설정 버킷 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 퍼블릭/ACL 과다 | s3.yaml.template |
| 5-49 | s3 | s3_bucket_public_write_acl | Public-Write ACL 설정 버킷 탐지 | aws.s3 | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 퍼블릭/ACL 과다 | s3.yaml.template |
| 5-50 | s3 | s3_bucket_secure_transport_policy | HTTPS 전용 접근 정책 미적용 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 정책 미설정 | s3.yaml.template |
| 5-51 | s3 | s3_bucket_server_access_logging_enabled | 서버 액세스 로깅 미설정 버킷 탐지 | aws.s3 | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 로깅 미설정 | s3.yaml.template |
| 5-52 | secretsmanager | secretsmanager_rotation_enabled | Secrets Manager 자동 로테이션 미설정 탐지 | aws.secrets-manager | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 로테이션 미설정 | secretsmanager.yaml.template |

---

## 6. 로깅/모니터링

| No. | 서비스 | 정책명 | 설명 | 리소스 | 권장 모드 | 권장 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 6-01 | cloudwatch | ccloudwatch_log_metric_filter_and_alarm_for_cloudtrail_config_changes_enabled | CloudTrail 설정 변경(업데이트/중지/삭제) 메트릭/알람 구성 점검 | aws.account | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | DeleteTrail, StopLogging, UpdateTrail | cloudwatch.yaml.template |
| 6-02 | cloudwatch | cloudtrail-cloudwatch-logs-attach | CloudTrail→CloudWatch Logs 미연결 시 자동 연결 | aws.cloudtrail | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 로깅 미설정 | cloudwatch.yaml.template |
| 6-03 | cloudwatch | cloudtrail-enable-cloudwatch-logs | CloudTrail 로그 연동 활성화 자동 수행 | aws.cloudtrail | cloudtrail | auto+notify | 🟢 조치완료 (good) | 중 | 중기 | UpdateTrail | cloudwatch.yaml.template |
| 6-04 | cloudwatch | cloudwatch-changes-to-vpcs-alarm-configured | VPC 생성/삭제/속성변경 이벤트 알림 구성 점검 | aws.ec2 | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | CreateVpc, DeleteVpc, ModifyVpcAttribute, ModifyVpcTenancy | cloudwatch.yaml.template |
| 6-05 | cloudwatch | cloudwatch_cross_account_sharing_disabled | Cross-account Log Group 리소스 정책 과다허용 탐지 | aws.log-group | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 정책/리소스 공개 | cloudwatch.yaml.template |
| 6-06 | cloudwatch | cloudwatch_log_metric_filter_and_alarm_for_aws_config_changes_enabled | AWS Config 레코더/채널 변경 탐지 메트릭/알람 점검 | aws.account | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | DeleteConfigurationRecorder, DeleteDeliveryChannel, PutConfigurationRecorder, PutDeliveryChannel, StopConfigurationRecorder | cloudwatch.yaml.template |
| 6-07 | cloudwatch | cloudwatch_log_metric_filter_authentication_failures | 콘솔 로그인 실패 이벤트 탐지 알람 점검 | aws.cloudtrail | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | ConsoleLogin | cloudwatch.yaml.template |
| 6-08 | cloudwatch | cloudwatch_log_metric_filter_aws_organizations_changes | AWS Organizations 변경 이벤트 알림 점검 | aws.account | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | AttachPolicy, CreateAccount, CreateOrganizationalUnit, DeleteOrganization, DeleteOrganizationalUnit, DetachPolicy, InviteAccountToOrganization | cloudwatch.yaml.template |
| 6-09 | cloudwatch | cloudwatch_log_metric_filter_disable_kms_key_deletion | KMS 키 비활성/삭제 예약 이벤트 알림 점검 | aws.kms-key | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | DisableKey, ScheduleKeyDeletion | cloudwatch.yaml.template |
| 6-10 | cloudwatch | cloudwatch_log_metric_filter_for_s3_bucket_policy_changes | S3 버킷 정책 추가/삭제 이벤트 알림 점검 | aws.s3 | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | DeleteBucketPolicy, PutBucketPolicy | cloudwatch.yaml.template |
| 6-11 | cloudwatch | cloudwatch_log_metric_filter_policy_changes | IAM 정책 생성/삭제/갱신 이벤트 알림 점검 | aws.cloudtrail | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | CreatePolicy, DeletePolicy, PutGroupPolicy, PutRolePolicy, PutUserPolicy | cloudwatch.yaml.template |
| 6-12 | cloudwatch | cloudwatch_log_metric_filter_root_usage | Root 콘솔 로그인 이벤트 알림 점검 | aws.account | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | ConsoleLogin | cloudwatch.yaml.template |
| 6-13 | cloudwatch | cloudwatch_log_metric_filter_security_group_changes | SG 인바운드 퍼블릭 허용 감지 → 자동 제거 | aws.security-group | cloudtrail | auto+notify | 🟢 조치완료 (good) | 상 | 단기 | AuthorizeSecurityGroupIngress | cloudwatch.yaml.template |
| 6-14 | cloudwatch | cloudwatch_log_metric_filter_sign_in_without_mfa | MFA 없이 성공한 콘솔 로그인 이벤트 알림 점검 | aws.cloudtrail | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | ConsoleLogin | cloudwatch.yaml.template |
| 6-15 | cloudwatch | cloudwatch_log_metric_filter_unauthorized_api_calls | 미인가 API 호출 탐지 메트릭/알람 부재 점검 | account | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | CloudTrail 미인가 API 이벤트 | cloudwatch.yaml.template |
| 6-16 | cloudwatch | monitor-network-gateway-changes | IGW/NAT GW 변경 이벤트 모니터링 | aws.cloudtrail | cloudtrail | notify-only | 🟠 경고 (warning) | 중 | 중기 | AttachInternetGateway, CreateInternetGateway, CreateNatGateway, DeleteInternetGateway, DeleteNatGateway, DetachInternetGateway | cloudwatch.yaml.template |
| 6-17 | cloudwatch | monitor-route-table-changes | 라우팅 테이블 변경 이벤트 모니터링 | aws.account | cloudtrail | notify-only | 🔴 위험 (danger) | 상 | 단기 | CreateRoute, DeleteRoute, ReplaceRoute | cloudwatch.yaml.template |
| 6-18 | cloudwatch | nacl-overly-permissive | 과도 허용 NACL 규칙 주기 점검 | aws.network-acl | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: NACL 과다허용 | cloudwatch.yaml.template |
| 6-19 | eventbridge | eventbridge_bus_cross_account_access | EventBridge 버스 교차계정 접근 과다허용 탐지 | aws.event-bus | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 정책 과다 | eventbridge.yaml.template |
| 6-20 | eventbridge | eventbridge_bus_exposed | EventBridge 버스 공개 노출 탐지 | aws.event-bus | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 공개 노출 | eventbridge.yaml.template |

---

## 7. 백업/DR

| No. | 서비스 | 정책명 | 설명 | 리소스 | 권장 모드 | 권장 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 7-01 | backup | backup_plans_exist | 백업 계획(Plan) 미존재 탐지 | aws.backup-plan | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 백업 미구성 | backup.yaml.template |
| 7-02 | backup | backup_reportplans_exist | 백업 리포트 플랜 미존재 탐지 | aws.account | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검: 백업 미구성 | backup.yaml.template |
| 7-03 | backup | backup_vaults_encrypted | Backup Vault 암호화 미적용 탐지 | aws.backup-vault | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 암호화 미적용 | backup.yaml.template |
| 7-04 | backup | backup_vaults_exist | Vault 미연동 백업 플랜 탐지 | aws.backup-plan | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검: 백업 미구성 | backup.yaml.template |

---

## 8. 기타

| No. | 서비스 | 정책명 | 설명 | 리소스 | 권장 모드 | 권장 조치 | 알림색상 | 위험도 | 조치기간 | 트리거조건 | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 8-01 | autoscaling | autoscaling_group_multiple_az | Auto Scaling Group의 다중 AZ 배포 점검 | aws.asg | periodic | notify-only | 🟠 경고 (warning) | 중 | 중기 | 주기 점검 | autoscaling.yaml.template |
| 8-02 | macie | macie_is_enabled | Macie 비활성 계정 탐지 | aws.account | periodic | notify-only | 🔴 위험 (danger) | 상 | 단기 | 주기 점검 | macie.yaml.template |

---

### 색상 신호 체계
- 🟢 **조치완료 (good)**: 자동조치가 성공적으로 수행되어 리스크가 해소됨
- 🟠 **경고 (warning)**: 운영 영향/합의 필요 또는 비실질 액션 중심(알림만)
- 🔴 **위험 (danger)**: 외부 노출/권한승격/암호화 미적용 등 고위험 상태

