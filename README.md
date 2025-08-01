# 🛡️ Cloud Custodian 자동화 인프라 (Terraform 기반)

이 프로젝트는 AWS 보안 정책을 자동으로 탐지하고 알림 및 대응하는 **Cloud Custodian 기반 자동화 인프라**입니다. Terraform으로 구성된 이 시스템은 CloudTrail 이벤트 발생 시 보안 위반 사항을 자동 감지하고, SQS를 통해 Slack 또는 이메일로 알림을 전송합니다.

---

## 🚀 주요 특징

* **CloudTrail 실시간 이벤트 감지** → Lambda 트리거
* **Cloud Custodian 정책 자동 실행** → SQS 메시지 생성
* **c7n-mailer**로 Slack 알림 연동 (심각도별 Webhook 분리)
* **Dead Letter Queue**로 메시지 유실 방지
* **모듈화된 Terraform 코드**로 유연한 재사용 가능

---

## 📁 디렉토리 구조

```
terraform/
├── main.tf                    # 전체 인프라 구성
├── variables.tf              # 공통 변수 정의
├── outputs.tf                # 결과 출력
├── provider.tf               # AWS provider 정의
├── Makefile                  # Lambda 빌드 및 Terraform 자동화
├── custodian_lambda.py       # CloudTrail Lambda 핸들러
├── c7n-mailer.yml            # c7n-mailer 설정 파일
├── generate-dev-tfvars.sh    # .env → dev.tfvars 자동 생성
│
├── env/
│   └── dev.tfvars            # 환경별 변수 정의 (.env 기반 생성)
│
├── modules/
│   ├── custodian-iam/        # Lambda 및 mailer IAM 역할
│   ├── custodian-sqs/        # SQS + DLQ 구성
│   └── custodian-trail/      # CloudTrail + 로그용 S3 버트
│
├── policies/
│   ├── cloudtrail/           # mode: cloudtrail 정책
│   └── periodic/             # mode: periodic 정책
```

---

## ⚙️ 설치 및 실행 방법

### 1. 필수 도구 설치

```bash
terraform -v        # >= 1.0
python3 --version   # >= 3.11
make --version
```

### 2. 환경번수 파일 생성

`.env 파일에 ACCOUNT_ID, QUEUE_URL에 (ACCOUNT_ID), AWS_REGION 그리고 3가지 slack webhook 주소를 입력해야 합니다.`

`.env` 파일 작성 예시:

```bash
ACCOUNT_ID=
AWS_REGION=
LAMBDA_ROLE=whs3-custodian-lambda-role
QUEUE_URL=https://sqs.ap-northeast-2.amazonaws.com/(ACCOUNT_ID)/whs3-security-alert-queue
GOOD_SLACK=https://hooks.slack.com/services/T00000000/B00000000/GOOD
WARNING_SLACK=https://hooks.slack.com/services/T00000000/B00000000/WARNING
DANGER_SLACK=https://hooks.slack.com/services/T00000000/B00000000/DANGER
```

### 3. Terraform 배포

```bash
# ./generate-dev-tfvars.sh 실행 권한 부여
chmod +x generate-dev-tfvars.sh

# dev.tfvars 자동 생성
./generate-dev-tfvars.sh

# .env 파일에 적은 것들이 제대로 반영되었는지 확인
cat env/dev.tfvars

# Terraform 초기화
terraform init

# 전체 인프라 배포 (build + deploy)
make all
```

---

## 🥪 정책 실행 방법

### ✅ Type: CloudTrail

**예시 정책 경로**: `policies/cloudtrail/type:cloudtrail인 정책 파일 이름.yml`

```bash
custodian run -s out policies/cloudtrail/type:cloudtrail인 정책 파일 이름.yml
```

### ✅ Type: Periodic

**예시 정책 경로**: `policies/periodic/type:periodic인 정책 파일 이름.yml`

```bash
custodian run -s out policies/periodic/type:periodic인 정책 파일 이름.yml
```

---

## 📦 Makefile 주요 명령어

```bash
make all              # 전체 배포(tfvars + validate + apply)
make tfvars           # .env → dev.tfvars 생성
make build-lambda     # custodian_lambda.py → .zip 패키지인
make deploy-policies  # 모든 정책 deploy (envsubst)
make run-cloudtrail   # cloudtrail 정책 직접 실행 (예외적 테스트용)
make run-periodic     # periodic 정책 직접 실행
```

---

## 📤 Terraform 출력값 예시

```bash
terraform output
```

* `custodian_notify_queue_url`
* `trail_bucket_name`
* `cloudtrail_arn`
* `custodian_lambda_role_arn`
* `eventbridge_rule_arn`
