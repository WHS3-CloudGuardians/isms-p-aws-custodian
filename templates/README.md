
# AWS 보안 점검 매트릭스 (Custodian 기반)

본 문서는 우리 조직의 Cloud Custodian 정책을 기준으로, **각 리소스/정책의 위험도, 실행 모드, 조치 수준(알림만/자동조치)**을 표로 정리하고
그 판단 기준을 명확히 설명한다.

## 1) 위험도 구분 (우리 조직 기준)
| 위험도 | 내    용 | 조치기간 | 비고 |
|---|---|---|---|
| 상 | 관리자 계정/주요 정보 유출 등 **치명적 피해**로 직결 가능 | 단기 | 예: 퍼블릭 접근, 권한승격 경로, MFA 미적용 등 |
| 중 | 노출된 정보를 통해 **추가 정보 유출/권한 확대** 우려 | 중기 | 예: 암호화/버전닝/로깅 미적용, 구성 취약 |
| 하 | 타 취약점과 연계 가능한 **잠재적 위험** | 장기 | 예: 하우스키핑/비용 중심 이슈 |

> 산정 방법: 외부노출성, 데이터/권한 민감도, 폭발반경, 악용 용이성 지표로 평가.  
> 템플릿에 지정된 `danger/warning`가 있으면 우선 반영하고, 없을 경우 키워드·리소스 기반 휴리스틱으로 보수적으로 산정.

## 2) 핵심 기준 요약
- **CloudTrail**: 변경 **즉시 위험**(예: SG 공개 인바운드, launch‑wizard SG, PAB/ACL/Policy 변경) → **실시간 탐지**, 안전하면 **자동조치**
- **Periodic**: **상태 컴플라이언스/레거시 보완**(예: RDS 백업, EBS 스냅샷/암호화, S3 라이프사이클) → **전수 점검**
- **자동조치 + 알림**: `remove-`/`set-`/`delete` 등 **실질적 조치**일 때, Slack=`good`
- **알림만**: 운영 영향·합의 필요 또는 **비실질 액션**(`tag`/`mark-for-op`/`post-finding` 등) → Slack=`warning`/`danger`
- **색상은 결과 신호**: 자동조치가 수행되면 **good**, 미조치면 **위험도 색상**(`danger`/`warning`) 사용

---

## 3) 전수 표 (리소스·정책별)
**열 설명**: 영역 / 서비스 / 정책명 / 설명 / 리소스 / 권장 모드 / 권장 조치 / **알림 색상(메시지)** / **위험도** / 조치기간 / 이벤트(CloudTrail) / 템플릿 파일

| 영역 | 서비스 | 정책명 | 설명 | 리소스 | 모드 | 조치 | 알림색상 | 위험도 | 조치기간 | 이벤트(CloudTrail) | 템플릿 파일 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 감사/컴플라이언스 | cloudtrail | cloudtrail_bucket_requires_mfa_delete | Detect S3 buckets with MFA Delete disabled and send alerts to Slack | aws.s3 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_cloudwatch_logging_enabled | If a CloudTrail trail is not integrated with CloudWatch Logs or logging is disabled, automatically configure the integration and send a Slack notification. | aws.cloudtrail | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_insights_exist | Detect and notify when CloudTrail Insights is disabled | aws.cloudtrail | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_kms_encryption_enabled | Detect CloudTrails that are not encrypted with KMS | aws.cloudtrail | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_log_file_validation_enabled | Send Slack notification when CloudTrail log file validation is disabled | aws.cloudtrail | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_logs_s3_bucket_access_logging_enabled | Notify when S3 bucket access logging is disabled | aws.s3 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_logs_s3_bucket_is_not_publicly_accessible | Send Slack notification when CloudTrail log bucket is publicly accessible | aws.s3 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_multi_region_enabled | Send Slack notification when CloudTrail is not enabled for multi-region logging | aws.cloudtrail | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_multi_region_or_no_management_events | Send Slack notification when CloudTrail is not logging in all regions or not capturing management events | aws.cloudtrail | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_s3_dataevents_read_enabled | Detect CloudTrail trails without S3 read data event logging | aws.cloudtrail | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | cloudtrail | cloudtrail_s3_dataevents_write_enabled | CloudTrail is not logging S3 object-level write events, making it impossible to track changes like object creation or deletion | aws.cloudtrail | periodic | notify-only | 경고(warning) | 중 | 중기 | - | cloudtrail.yaml.template |
| 감사/컴플라이언스 | config | config_recorder_all_regions_enabled | | | aws.config-recorder | periodic | notify-only | 경고(warning) | 중 | 중기 | - | config.yaml.template |
| 감사/컴플라이언스 | securityhub | securityhub_enabled | | | aws.account | periodic | notify-only | 위험(danger) | 상 | 단기 | - | securityhub.yaml.template |
| 계정 관리 | accessanalyzer | accessanalyzer_enabled | | | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | accessanalyzer.yaml.template |
| 계정 관리 | account | account_maintain_current_contact_details | | | aws.org-account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | account.yaml.template |
| 계정 관리 | account | account_maintain_different_contact_details_to #이름 길이가 64자를 넘어서 줄임 | | | aws.org-account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | account.yaml.template |
| 계정 관리 | account | account_security_contact_information_is_registered | | | aws.org-account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | account.yaml.template |
| 계정 관리 | account | account_security_questions_are_registered_in_account | | | aws.org-account | periodic | notify-only | 위험(danger) | 상 | 단기 | - | account.yaml.template |
| 계정 관리 | organization | organizations_scp_check_deny_regions | | | aws.org-account | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | organization.yaml.template |
| 계정 관리 | organization | organizations_tags_policies_enabled_and_attached | | | aws.org-account | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | organization.yaml.template |
| 권한 관리 | iam | iam_administrator_access_with_mfa | Detect IAM users with AdministratorAccess but no MFA, then send Slack alert. | aws.iam-user | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_avoid_root_usage | Detect AWS root account usage and send Slack alert for review. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_aws_attached_policy_no_administrative_privileges | Detect users with AWS-managed AdministratorAccess and send Slack alert. | aws.iam-user | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_check_saml_providers_sts | Detect SAML providers without sts.amazonaws.com in ARN, then send Slack alert. | aws.iam-saml-provider | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_customer_attached_policy_no_adminis | Detect attached customer-managed policies with '*:*' privilege, then send Slack alert. | aws.iam-policy | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_customer_unattached_policy_no_adminis | Detect unattached customer-managed policies that allow all actions, then send Slack alert. | aws.iam-policy | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_group_administrator_access_policy | Detect IAM groups with AdministratorAccess attached and send Slack alert. | aws.iam-group | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_inline_policy_allows_privilege_escalation | Detect IAM users whose inline policies allow privilege escalation (e.g., iam:PassRole), then send Slack alert. | aws.iam-user | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_inline_policy_no_administrative_privileges | Detect inline policies with '*:*' actions and send Slack alert. | aws.iam-user | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_inline_policy_no_full_access_to_cloudtrail | Detect inline policies with cloudtrail:* privileges and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_inline_policy_no_full_access_to_kms | Detect inline policies with kms:* privileges and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_no_custom_policy_permissive_role_assumption | Detect custom IAM policies that allow sts:AssumeRole on all resources, then send Slack alert. | aws.iam-policy | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_no_root_access_key | Detect AWS root account with active access key(s), then send Slack alert. | aws.account | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_password_policy_expires_90_days_or_less | Detect AWS account password policies that do not expire passwords within 90 days, then send Slack alert. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_password_policy_lowercase | Detect AWS account password policies that do not require lowercase characters, then send Slack alert. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_password_policy_minimum_length_14 | Detect AWS account password policies with minimum length less than 14 and send Slack alert. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_password_policy_number | Detect AWS account password policies that do not require numbers and send Slack alert. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_password_policy_reuse_24 | Detect AWS account password policies allowing reuse fewer than 24 times and send Slack alert. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_password_policy_symbol | Detect AWS account password policies that do not require symbols and send Slack alert. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_password_policy_uppercase | Detect AWS account password policies that do not require uppercase letters and send Slack alert. | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_policy_allows_privilege_escalation | Detect IAM policies that include iam:PassRole and send Slack alert. | aws.iam-policy | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_policy_attached_only_to_group_or_roles | Detect IAM policies attached directly to users or groups and send Slack alert. | aws.iam-policy | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_policy_no_full_access_to_cloudtrail | Detect IAM policies that grant full CloudTrail privileges and send Slack alert. | aws.iam-policy | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_policy_no_full_access_to_kms | Detect IAM policies that grant full KMS privileges and send Slack alert. | aws.iam-policy | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_role_cross_service_confused_deputy_prevention | Detect IAM roles whose trust policy omits StringEquals condition and send Slack alert (confused deputy prevention). | aws.iam-role | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_root_hardware_mfa_enabled | Detect root account without hardware MFA and send Slack alert. | aws.account | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_root_mfa_enabled | Detect root account without any MFA and send Slack alert. | aws.account | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_rotate_access_key_90_days | Detect IAM user access keys last rotated over 90 days ago and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_securityaudit_role_created | Detect absence of SecurityAudit role, create if missing, then send Slack alert. | aws.iam-role | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_support_role_created | Detect absence of Support role, create if missing, then send Slack alert. | aws.iam-role | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_accesskey_unused | Detect IAM users with access keys unused for over 90 days and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_administrator_access_policy | Detect IAM users with AdministratorAccess policy and send Slack alert. | aws.iam-user | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_console_access_unused | Detect console-only IAM users (no access key usage) and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_hardware_mfa_enabled | Detect IAM users without hardware MFA and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_mfa_enabled_console_access | Detect IAM users with console access and no active MFA and send Slack alert. | aws.iam-user | periodic | notify-only | 위험(danger) | 상 | 단기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_no_setup_initial_access_key | Detect console users retaining initial access keys and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_two_active_access_key | Detect IAM users with two or more active access keys and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | iam | iam_user_with_temporary_credentials | Detect IAM users with active temporary (STS) credentials and send Slack alert. | aws.iam-user | periodic | notify-only | 경고(warning) | 중 | 중기 | - | iam.yaml.template |
| 권한 관리 | kms | kms_cmk_are_used | | | aws.kms-key | periodic | notify-only | 경고(warning) | 중 | 중기 | - | kms.yaml.template |
| 권한 관리 | kms | kms_cmk_not_deleted_unintentionally | | | aws.kms-key | periodic | notify-only | 경고(warning) | 중 | 중기 | - | kms.yaml.template |
| 권한 관리 | kms | kms_cmk_rotation_enabled | | | aws.kms-key | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | kms.yaml.template |
| 권한 관리 | kms | kms_key_not_publicly_accessible | | | aws.kms-key | periodic | notify-only | 경고(warning) | 중 | 중기 | - | kms.yaml.template |
| 기타 | autoscaling | autoscaling_group_multiple_az | Ensure Auto Scaling Groups span multiple Availability Zones | aws.asg | periodic | notify-only | 경고(warning) | 중 | 중기 | - | autoscaling.yaml.template |
| 기타 | macie | macie_is_enabled | "Alert: Macie is disabled" | aws.account | periodic | notify-only | 위험(danger) | 상 | 단기 | - | macie.yaml.template |
| 네트워크/엣지 | apigateway | apigateway_restapi_client_certificate_enabled | | | aws.rest-api | periodic | notify-only | 위험(danger) | 상 | 단기 | - | apigateway.yaml.template |
| 네트워크/엣지 | apigateway | apigateway_restapi_logging_enabled | | | aws.rest-api | periodic | notify-only | 경고(warning) | 중 | 중기 | - | apigateway.yaml.template |
| 네트워크/엣지 | apigateway | apigateway_restapi_public | | | aws.rest-api | periodic | notify-only | 위험(danger) | 상 | 단기 | - | apigateway.yaml.template |
| 네트워크/엣지 | cloudfront | cloudfront_distributions_field_level_encrypt_enabled | CloudFront distributions field level encryption disabled alert | aws.distribution | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudfront.yaml.template |
| 네트워크/엣지 | cloudfront | cloudfront_distributions_geo_restrictions_enabled | cloudfront distributions geo restrictions disabled alert | aws.distribution | periodic | notify-only | 경고(warning) | 중 | 중기 | - | cloudfront.yaml.template |
| 네트워크/엣지 | cloudfront | cloudfront_distributions_https_enabled | cloudfront distributions https disabled alert | aws.distribution | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudfront.yaml.template |
| 네트워크/엣지 | cloudfront | cloudfront_distributions_logging_enabled | cloudfront distributions logging disabled alert | aws.distribution | periodic | notify-only | 경고(warning) | 중 | 중기 | - | cloudfront.yaml.template |
| 네트워크/엣지 | cloudfront | cloudfront_distributions_using_deprecated_ssl_protocol | cloudfront distributions using legacy ssl protocols alert | aws.distribution | periodic | notify-only | 경고(warning) | 중 | 중기 | - | cloudfront.yaml.template |
| 네트워크/엣지 | cloudfront | cloudfront_distributions_using_waf | cloudfront distributions using none waf alert | aws.distribution | periodic | notify-only | 경고(warning) | 중 | 중기 | - | cloudfront.yaml.template |
| 네트워크/엣지 | elb | elbv2_deletion_protection | Ensure deletion protection is enabled on Application Load Balancers | aws.app-elb | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | CreateLoadBalancer | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_desync_mitigation_mode | Ensure ALB desync mitigation mode is switched from monitoring to defensive | aws.app-elb | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | CreateLoadBalancer, ModifyLoadBalancerAttributes | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_insecure_listeners | Detect any v2 load balancer listeners not using TLS/HTTPS | aws.app-elb | periodic | notify-only | 위험(danger) | 상 | 단기 | - | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_insecure_ssl_ciphers | Detect ALB listeners using deprecated SSL policies and notify | aws.app-elb | periodic | notify-only | 위험(danger) | 상 | 단기 | - | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_internet_facing | Detect internet-facing ALBs for security review | aws.app-elb | periodic | notify-only | 경고(warning) | 중 | 중기 | - | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_is_in_multiple_az | Ensure ALB is deployed in multiple Availability Zones for high availability | aws.app-elb | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | CreateLoadBalancer | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_listeners_underneath | Detect Application Load Balancers without any listeners | aws.app-elb | periodic | notify-only | 경고(warning) | 중 | 중기 | - | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_logging_enabled | Ensure ELBv2 access logging is enabled and logs are stored in S3 for traffic analysis | aws.app-elb | periodic | notify-only | 위험(danger) | 상 | 단기 | - | elb.yaml.template |
| 네트워크/엣지 | elb | elbv2_waf_acl_attached | Alert on ALBs without a WAFv2 or WAF Web ACL attached | aws.app-elb | periodic | notify-only | 위험(danger) | 상 | 단기 | - | elb.yaml.template |
| 네트워크/엣지 | networkfirewall | networkfirewall_in_all_vpc | Alert on VPCs without AWS Network Firewall deployed | aws.vpc | periodic | notify-only | 위험(danger) | 상 | 단기 | - | networkfirewall.yaml.template |
| 네트워크/엣지 | route53 | route53_public_hosted_zones_cloudwatch_logging_enabled | | | aws.hostedzone | periodic | notify-only | 경고(warning) | 중 | 중기 | - | route53.yaml.template |
| 네트워크/엣지 | vpc | vpc-subnet-disable-default-public-ip | Disables default public IP assignment on new EC2 instances launched in subnets | aws.subnet | periodic | notify-only | 경고(warning) | 상 | 단기 | - | vpc.yaml.template |
| 네트워크/엣지 | vpc | vpc_different_regions | Alert when a region has only one VPC | aws.vpc | periodic | notify-only | 경고(warning) | 중 | 중기 | - | vpc.yaml.template |
| 네트워크/엣지 | vpc | vpc_flow_logs_enabled | Ensure VPC Flow Logs are enabled for traffic monitoring | aws.vpc | periodic | notify-only | 위험(danger) | 상 | 단기 | - | vpc.yaml.template |
| 네트워크/엣지 | vpc | vpc_subnet_different_az | Alert on VPCs with subnets in only one availability zone | aws.vpc | periodic | notify-only | 경고(warning) | 중 | 중기 | - | vpc.yaml.template |
| 네트워크/엣지 | vpc | vpc_subnet_separate_private_public | Alert VPCs that have only public subnets without any private subnets | aws.vpc | periodic | notify-only | 경고(warning) | 중 | 중기 | - | vpc.yaml.template |
| 데이터 보호 | athena | athena_workgroup_encryption | | | aws.athena-work-group | periodic | notify-only | 경고(warning) | 중 | 중기 | - | athena.yaml.template |
| 데이터 보호 | athena | athena_workgroup_enforce_configuration | | | aws.athena-work-group | periodic | notify-only | 경고(warning) | 중 | 중기 | - | athena.yaml.template |
| 데이터 보호 | dynamodb | dynamodb_tables_kms_cmk_encryption_enabled | | | aws.dynamodb-table | periodic | notify-only | 경고(warning) | 중 | 중기 | - | dynamodb.yaml.template |
| 데이터 보호 | dynamodb | dynamodb_tables_pitr_enabled | | | aws.dynamodb-table | periodic | notify-only | 위험(danger) | 상 | 단기 | - | dynamodb.yaml.template |
| 데이터 보호 | efs | efs_encryption_at_rest_enabled | "Alert: EFS Without encryption" | aws.efs | periodic | notify-only | 위험(danger) | 상 | 단기 | - | efs.yaml.template |
| 데이터 보호 | efs | efs_have_backup_enabled | "Alert: EFS Without Backup" | aws.efs | periodic | notify-only | 위험(danger) | 상 | 단기 | - | efs.yaml.template |
| 데이터 보호 | efs | efs_not_publicly_accessible | "Alert: EFS With public access" | aws.security-group | periodic | notify-only | 위험(danger) | 상 | 단기 | - | efs.yaml.template |
| 데이터 보호 | elasticache | elasticache_cluster_uses_public_subnet | | | aws.cache-subnet-group | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | CreateReplicationGroup, ModifyReplicationGroup | elasticache.yaml.template |
| 데이터 보호 | elasticache | elasticache_redis_cluster_auto_minor_version_upgrades | | | aws.elasticache-group | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | CreateReplicationGroup, ModifyReplicationGroup | elasticache.yaml.template |
| 데이터 보호 | elasticache | elasticache_redis_cluster_backup_enabled | | | aws.elasticache-group | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | CreateReplicationGroup, ModifyReplicationGroup | elasticache.yaml.template |
| 데이터 보호 | elasticache | elasticache_redis_cluster_in_transit_encrypt_enabled | | | aws.elasticache-group | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | CreateReplicationGroup, ModifyReplicationGroup | elasticache.yaml.template |
| 데이터 보호 | elasticache | elasticache_redis_cluster_multi_az_enabled | | | aws.elasticache-group | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | CreateReplicationGroup, ModifyReplicationGroup | elasticache.yaml.template |
| 데이터 보호 | elasticache | elasticache_redis_cluster_rest_encryption_enabled | | | aws.elasticache-group | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | CreateReplicationGroup, ModifyReplicationGroup | elasticache.yaml.template |
| 데이터 보호 | emr | emr_cluster_account_public_block_enabled | | | aws.emr | periodic | notify-only | 경고(warning) | 상 | 단기 | - | emr.yaml.template |
| 데이터 보호 | glue | glue_etl_jobs_amazon_s3_encryption_enabled | | | aws.glue-security-configuration | periodic | notify-only | 위험(danger) | 상 | 단기 | - | glue.yaml.template |
| 데이터 보호 | glue | glue_etl_jobs_cloudwatch_logs_encryption_enabled | | | aws.glue-security-configuration | periodic | notify-only | 경고(warning) | 중 | 중기 | - | glue.yaml.template |
| 데이터 보호 | glue | glue_etl_jobs_job_bookmark_encryption_enabled | | | aws.glue-security-configuration | periodic | notify-only | 경고(warning) | 중 | 중기 | - | glue.yaml.template |
| 데이터 보호 | rds | rds_instance_backup_enabled | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_certificate_expiration | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_copy_tags_to_snapshots | | | aws.rds | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_default_admin | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_deletion_protection | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_deprecated_engine_version | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_enhanced_monitoring_enabled | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_event_subscription_security_groups | | | aws.rds-subscription | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_iam_authentication_enabled | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_integration_cloudwatch_logs | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_minor_version_upgrade_enabled | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_multi_az | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_no_public_access | | | aws.rds | periodic | notify-only | 경고(warning) | 상 | 단기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_storage_encrypted | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_instance_transport_encrypted | | | aws.rds | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_snapshots_encrypted | | | aws.rds-snapshot | periodic | notify-only | 경고(warning) | 중 | 중기 | - | rds.yaml.template |
| 데이터 보호 | rds | rds_snapshots_public_access | | | aws.rds-snapshot | periodic | auto+notify | 조치완료(good) | 상 | 단기 | - | rds.yaml.template |
| 데이터 보호 | redshift | redshift_cluster_audit_logging | | | aws.redshift | periodic | notify-only | 위험(danger) | 상 | 단기 | - | redshift.yaml.template |
| 데이터 보호 | s3 | s3_account_level_public_access_blocks | Detect S3 public access block settings at the account level | aws.account | periodic | notify-only | 위험(danger) | 상 | 단기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_acl_prohibited | "Alert: S3 With acl ACL" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_cross_region_replication | "Alert: S3 Without Cross-Region Replication" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_default_encryption | "Action & Alert : S3 Without default encryption" | aws.s3 | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_kms_encryption | "Alert : S3 Without kms encryption" | aws.s3 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_level_public_access_block | "Alert: S3 Public Access Block 변경 실시간 감지" | aws.s3 | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | DeleteBucketPublicAccessBlock, PutBucketPublicAccessBlock | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_lifecycle_enabled | "Alert: S3 Without lifecycle" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_no_mfa_delete | "Alert: S3 Without MFA delete" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_object_lock | "Alert: S3 Without Object Lock" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_object_versioning | "Alert: S3 Without versioning" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_policy_public_write_access | "Action & Alert: S3 퍼블릭 쓰기 정책 변경 실시간 감지" | aws.s3 | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | PutBucketPolicy | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_public_access | "Action & Alert: S3 버킷 퍼블릭 액세스 실시간 감지" | aws.s3 | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | PutBucketAcl, PutBucketPolicy | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_public_list_acl | "Alert: S3 With public list acl" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_public_write_acl | "Alert: S3 With public write acl" | aws.s3 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_secure_transport_policy | "Alert: S3 Without HTTPS access policy" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | s3 | s3_bucket_server_access_logging_enabled | "Alert: S3 Without server access logging" | aws.s3 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | s3.yaml.template |
| 데이터 보호 | secretsmanager | secretsmanager_rotation_enabled | | | aws.secrets-manager | periodic | notify-only | 위험(danger) | 상 | 단기 | - | secretsmanager.yaml.template |
| 로깅/모니터링 | cloudwatch | ccloudwatch_log_metric_filter_and_alarm_for_cloudtrail_config_changes_enabled | Detects CloudTrail configuration changes like update, stop, or delete trail. | aws.account | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | DeleteTrail, StopLogging, UpdateTrail | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudtrail-cloudwatch-logs-attach | Automatically connects CloudTrail to CloudWatch Logs if not configured. | aws.cloudtrail | periodic | notify-only | 경고(warning) | 중 | 중기 | - | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudtrail-enable-cloudwatch-logs | | | aws.cloudtrail | cloudtrail | auto+notify | 조치완료(good) | 중 | 중기 | UpdateTrail | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch-changes-to-vpcs-alarm-configured | | | aws.ec2 | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | CreateVpc, DeleteVpc, ModifyVpcAttribute, ModifyVpcTenancy | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_cross_account_sharing_disabled | Detect and notify when CloudWatch Logs resource policy allows cross-account access. | aws.log-group | periodic | notify-only | 위험(danger) | 상 | 단기 | - | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_and_alarm_for_aws_config_changes_enabled | Detects when AWS Config recorder settings are modified. | aws.account | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | DeleteConfigurationRecorder, DeleteDeliveryChannel, PutConfigurationRecorder, PutDeliveryChannel, StopConfigurationRecorder | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_authentication_failures | Detection of a failed AWS Console login event. | aws.cloudtrail | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | ConsoleLogin | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_aws_organizations_changes | Notification on AWS Organizations change events. | aws.account | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | AttachPolicy, CreateAccount, CreateOrganizationalUnit, DeleteOrganization, DeleteOrganizationalUnit, DetachPolicy, InviteAccountToOrganization | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_disable_kms_key_deletion | Detect KMS key disable or scheduled deletion events and notify for manual review. | aws.kms-key | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | DisableKey, ScheduleKeyDeletion | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_for_s3_bucket_policy_changes | Notify when S3 bucket policy is added or removed via CloudTrail | aws.s3 | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | DeleteBucketPolicy, PutBucketPolicy | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_policy_changes | Detects IAM policy changes such as creation, deletion, or updates to user, group, or role policies. | aws.cloudtrail | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | CreatePolicy, DeletePolicy, PutGroupPolicy, PutRolePolicy, PutUserPolicy | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_root_usage | AWS root account is used for console login. | aws.account | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | ConsoleLogin | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_security_group_changes | Detects when a security group ingress rule allows public (0.0.0.0/0) access and removes it. | aws.security-group | cloudtrail | auto+notify | 조치완료(good) | 상 | 단기 | AuthorizeSecurityGroupIngress | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_sign_in_without_mfa | Missing log filter and alarm for successful console login events without MFA. | aws.cloudtrail | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | ConsoleLogin | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | cloudwatch_log_metric_filter_unauthorized_api_calls | Missing CloudWatch metric filter and alarm for unauthorized API calls, violating security monitoring and access control requirements. | account | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | - | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | monitor-network-gateway-changes | Detect changes to Internet and NAT gateways using CloudTrail events. | aws.cloudtrail | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | AttachInternetGateway, CreateInternetGateway, CreateNatGateway, DeleteInternetGateway, DeleteNatGateway, DetachInternetGateway | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | monitor-route-table-changes | Monitor route table changes that may pose a risk of unauthorized network routing. | aws.account | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | CreateRoute, DeleteRoute, ReplaceRoute | cloudwatch.yaml.template |
| 로깅/모니터링 | cloudwatch | nacl-overly-permissive | | | aws.network-acl | periodic | notify-only | 경고(warning) | 중 | 중기 | - | cloudwatch.yaml.template |
| 로깅/모니터링 | eventbridge | eventbridge_bus_cross_account_access | "Alert: eventbridge bus cross account access" | aws.event-bus | periodic | notify-only | 위험(danger) | 상 | 단기 | - | eventbridge.yaml.template |
| 로깅/모니터링 | eventbridge | eventbridge_bus_exposed | "Alert: eventbridge bus exposed" | aws.event-bus | periodic | notify-only | 위험(danger) | 상 | 단기 | - | eventbridge.yaml.template |
| 백업/DR | backup | backup_plans_exist | "Alert: No Backup Plan" | aws.backup-plan | periodic | notify-only | 경고(warning) | 중 | 중기 | - | backup.yaml.template |
| 백업/DR | backup | backup_reportplans_exist | "Alert: No Backup Report Plan" | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | backup.yaml.template |
| 백업/DR | backup | backup_vaults_encrypted | "Alert: Backup Vault Without Encryption" | aws.backup-vault | periodic | notify-only | 위험(danger) | 상 | 단기 | - | backup.yaml.template |
| 백업/DR | backup | backup_vaults_exist | "Alert: Backup Plan Without Vault" | aws.backup-plan | periodic | notify-only | 위험(danger) | 상 | 단기 | - | backup.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_default_encryption | Automatic activation and notification transmission when default EBS encryption is turned off | aws.account | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | DisableEbsEncryptionByDefault | ec2_ebs.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_default_encryption | Automatic activation and notification transmission when default EBS encryption is turned off | aws.account | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | DisableEbsEncryptionByDefault | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_snapshots_encrypted | Send notification when unencrypted EBS snapshot is detected | aws.ebs-snapshot | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2_ebs.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_snapshots_encrypted | Send notification when unencrypted EBS snapshot is detected | aws.ebs-snapshot | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_volume_encryption | Send notifications and create snapshots when unencrypted EBS volumes are detected | aws.ebs | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2_ebs.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_volume_encryption | Send notifications and create snapshots when unencrypted EBS volumes are detected | aws.ebs | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_volume_snapshots_exists | Creating volume snapshots and copying tags for EC2 instances without snapshots | aws.ebs | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_ebs.yaml.template |
| 컴퓨트 | ec2 | ec2_ebs_volume_snapshots_exists | Creating volume snapshots and copying tags for EC2 instances without snapshots | aws.ebs | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_elastic_ip_unassigned | Detect Elastic IPs not connected to EC2 and target tags for cost optimization | aws.elastic-ip | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_others.yaml.template |
| 컴퓨트 | ec2 | ec2_elastic_ip_unassigned | Detect Elastic IPs not connected to EC2 and target tags for cost optimization | aws.elastic-ip | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_account_imdsv2_enabled | Force IMDS basic token settings to be required for accounts | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_account_imdsv2_enabled | Force IMDS basic token settings to be required for accounts | aws.account | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_detailed_monitoring_enabled | When detailed monitoring of EC2 instances is disabled, switch it to enabled (additional charges may apply) | aws.ec2 | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_detailed_monitoring_enabled | When detailed monitoring of EC2 instances is disabled, switch it to enabled (additional charges may apply) | aws.ec2 | periodic | auto+notify | 조치완료(good) | 중 | 중기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_imdsv2_enabled | If the endpoint is disabled when a new instance is created, enable the endpoint | aws.ec2 | cloudtrail | auto+notify | 조치완료(good) | 중 | 중기 | RunInstances | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_imdsv2_enabled | If the endpoint is disabled when a new instance is created, enable the endpoint | aws.ec2 | cloudtrail | auto+notify | 조치완료(good) | 중 | 중기 | RunInstances | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_internet_facing_with_instance_profile | Check IAM instance profile for instances with public IP addresses notification | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_internet_facing_with_instance_profile | Check IAM instance profile for instances with public IP addresses notification | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_managed_by_ssm | Check if EC2 instances are managed by SSM and notify via Slack | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_managed_by_ssm | Check if EC2 instances are managed by SSM and notify via Slack | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_older_than_specific_days | Send a notification if there are EC2 instances that are older than a certain number of days. | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_older_than_specific_days | Send a notification if there are EC2 instances that are older than a certain number of days. | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_port | | | aws.ec2 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_port | | | aws.ec2 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_profile_attached | Find EC2 instances that are not connected to IAM instance profiles and send notifications | aws.ec2 | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | RunInstances | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_profile_attached | Find EC2 instances that are not connected to IAM instance profiles and send notifications | aws.ec2 | cloudtrail | notify-only | 경고(warning) | 중 | 중기 | RunInstances | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_public_ip | Find EC2 instances with public IP addresses, attach the “PubliclyAccessible” tag, and stop them if necessary | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_public_ip | Find EC2 instances with public IP addresses, attach the “PubliclyAccessible” tag, and stop them if necessary | aws.ec2 | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_secrets_user_data | Instance tags and notifications found with hard-coded secret information in EC2 UserData | aws.ec2 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_instance_secrets_user_data | Instance tags and notifications found with hard-coded secret information in EC2 UserData | aws.ec2 | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2_instance.yaml.template |
| 컴퓨트 | ec2 | ec2_launch_template_no_secrets | EC2 시작 템플릿 UserData 내에 하드코드된 시크릿 정보가 포함된 템플릿을 태그하고 알림 | aws.launch-template-version | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2_others.yaml.template |
| 컴퓨트 | ec2 | ec2_launch_template_no_secrets | EC2 시작 템플릿 UserData 내에 하드코드된 시크릿 정보가 포함된 템플릿을 태그하고 알림 | aws.launch-template-version | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_networkacl_allow_ingress_any_port | Detect whether the network ACL allows inbound access from 0.0.0.0/0 for all ports | aws.network-acl | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2_others.yaml.template |
| 컴퓨트 | ec2 | ec2_networkacl_allow_ingress_any_port | Detect whether the network ACL allows inbound access from 0.0.0.0/0 for all ports | aws.network-acl | periodic | notify-only | 위험(danger) | 상 | 단기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_networkacl_allow_ingress_tcp_port_22 | Detect whether the network ACL allows inbound access from 0.0.0.0/0 for the SSH port (22) | aws.network-acl | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_others.yaml.template |
| 컴퓨트 | ec2 | ec2_networkacl_allow_ingress_tcp_port_22 | Detect whether the network ACL allows inbound access from 0.0.0.0/0 for the SSH port (22) | aws.network-acl | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_networkacl_allow_ingress_tcp_port_3389 | Detect whether the network ACL allows inbound access from 0.0.0.0/0 for the RDP port (3389) | aws.network-acl | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_others.yaml.template |
| 컴퓨트 | ec2 | ec2_networkacl_allow_ingress_tcp_port_3389 | Detect whether the network ACL allows inbound access from 0.0.0.0/0 for the RDP port (3389) | aws.network-acl | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_allow | | | aws.security-group | cloudtrail | auto+notify | 조치완료(good) | 상 | 단기 | AuthorizeSecurityGroupIngress | ec2_securitygroup.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_allow | | | aws.security-group | cloudtrail | auto+notify | 조치완료(good) | 상 | 단기 | AuthorizeSecurityGroupIngress | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_default_restrict_traffic | | | aws.security-group | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2_securitygroup.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_default_restrict_traffic | | | aws.security-group | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_from_launch_wizard | | | aws.security-group | cloudtrail | auto+notify | 조치완료(good) | 상 | 단기 | CreateSecurityGroup | ec2_securitygroup.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_from_launch_wizard | | | aws.security-group | cloudtrail | auto+notify | 조치완료(good) | 상 | 단기 | CreateSecurityGroup | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_not_used | Unused security groups can be misused or contaminated, so a Slack notification is sent every month through scheduled batch execution. | aws.security-group | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2_securitygroup.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_not_used | Unused security groups can be misused or contaminated, so a Slack notification is sent every month through scheduled batch execution. | aws.security-group | periodic | notify-only | 경고(warning) | 중 | 중기 | - | ec2.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_with_many_ingress_egress_rules | | | aws.security-group | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2_securitygroup.yaml.template |
| 컴퓨트 | ec2 | ec2_securitygroup_with_many_ingress_egress_rules | | | aws.security-group | cloudtrail | notify-only | 위험(danger) | 상 | 단기 | AuthorizeSecurityGroupEgress, AuthorizeSecurityGroupIngress | ec2.yaml.template |
| 컴퓨트 | lambda | awslambda-function-inside-vpc | "Alert: Lambda function outside vpc" | aws.lambda | periodic | notify-only | 경고(warning) | 중 | 중기 | - | lambda.yaml.template |
| 컴퓨트 | lambda | awslambda-function-no-secrets-in-variables | "Alert: Lambda function secrets in variables" | aws.lambda | periodic | notify-only | 위험(danger) | 상 | 단기 | - | lambda.yaml.template |
| 컴퓨트 | lambda | awslambda-function-not-publicly-accessible | "Alert: Lambda function publicly accessible" | aws.lambda | periodic | notify-only | 위험(danger) | 상 | 단기 | - | lambda.yaml.template |
| 컴퓨트 | lambda | awslambda-function-using-supported-runtimes | "Alert: Lambda function Without support runtimes" | aws.lambda | periodic | notify-only | 경고(warning) | 중 | 중기 | - | lambda.yaml.template |
| 컴퓨트 | lambda | awslambda_function_inside_vpc | | | aws.lambda | periodic | notify-only | 경고(warning) | 중 | 중기 | - | lambda.yaml.template |
| 컴퓨트 | lambda | lambda-cloudtrail-logging-enabled | "Alert: No Logging in Lambda function invoke" | aws.cloudtrail | periodic | notify-only | 위험(danger) | 상 | 단기 | - | lambda.yaml.template |
| 컴퓨트 | lambda | lambda_func_cloudtrail_log_enabled | | | aws.lambda | periodic | notify-only | 위험(danger) | 상 | 단기 | - | lambda.yaml.template |
