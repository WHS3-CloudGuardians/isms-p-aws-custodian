<div align="center">
  
# isms-p-aws-custodian 
### AWS 환경에서의 Prowler & CloudCustodian 기반 ISMS-P 대응 자동화 오픈소스 툴

[![화이트햇 스쿨](https://img.shields.io/badge/화이트햇_스쿨_3기-blueviolet?style=flat)]()  
[![구름수비대](https://img.shields.io/badge/구름수비대-팀-blue?style=flat&logo=cloud)]()
[![버전](https://img.shields.io/badge/version-0.1.0-green?style=flat&logo=cloud)]()
![라이센스](https://img.shields.io/github/license/WHS3-CloudGuardians/isms-p-aws-custodian)

github/license
</div>

---

## 개요

### 목적
- 클라우드 보안 위협 증가와 수동 점검의 한계를 극복하기 위한 자동화 대응 시스템 구축
- 오픈소스를 기반으로 AWS 환경에서 ISMS-P 중심의 보안 점검 및 대응 자동화 구현

### 기능
1. 이벤트 기반 탐지/주기적 탐지로 AWS 환경에서의 ISMS-P 기준 준수
2. **보안 점검 및 대응 자동화**: Prowler로 취약점 점검 -> 점검 결과의 CHECKID와 동일한 이름의 Cloud Custodian 정책으로 취약점 조치
3. **CLI 명령어 제공**: 누구나 쉽게 Cloud Custodian 정책 생성 및 배포 가능

### 공식 노션
- [AWS 보안 및 컴플라이언스 자동화 가이드](https://www.notion.so/AWS-23fc86faa56f80ce9865ffe805df09e8?source=copy_link)
- [isms-p-aws-custodian 사용 가이드](https://www.notion.so/isms-p-aws-custodian-240c86faa56f8074a5f1d0a4378d6f24?source=copy_link)
---

## 사용 방법
> Prowler, Cloud Custodian의 설치 방법은 설명하지 않습니다. Prowler, Cloud Custodian의 공식 문서 또는 구름수비대 팀 공식 노션을 참고하세요.
> custodian 가상 환경이 꺼져있다면 `source custodian/bin/activate`를 입력해 활성화하세요.

### isms-p-aws-custodian 설치

**Git 리포지토리 클론**
```console
# git clone https://github.com/WHS3-CloudGuardians/isms-p-aws-custodian.git
# 테스트용은 아래
git clone --branch test/python-scripts https://github.com/WHS3-CloudGuardians/isms-p-aws-custodian.git
```
**의존성 설치**
```console
# isms-p-aws-custodian 경로로 이동 후
pip install -e .
```

### 환경 설정
> 정책을 생성하기 전에 AWS 환경을 세팅하고 .env 파일 구성을 완료하세요. .env파일에 빈 항목이 있으면 정책이 생성되지 않습니다.

**AWS 환경 세팅용 테라폼 배포 (선택 사항)**
- 이미 Cloud Custodian 실행을 위한 AWS 환경이 갖춰져 있다면 건너뛰고 진행하세요.
```console
cd ./custodian-setup
```
```console
terraform init
terraform plan
terraform apply
```
**`.env` 파일 구성**
- 정책을 생성하기 전에 자신의 환경에 맞게 모든 항목을 전부 채워넣어 주세요. 
```console
# 예시
ACCOUNT_ID=000123456789
AWS_REGION=ap-northeast-2
LAMBDA_ROLE=arn:aws:iam::000123456789:role/custodian-lambda-role
MAILER_ROLE=arn:aws:iam::000123456789:role/c7n-mailer-role
QUEUE_URL=https://sqs.ap-northeast-2.amazonaws.com/000123456789/custodian-notify-queue
GOOD_SLACK=https://hooks.slack.com/services/AAA/BBB/CCC
WARNING_SLACK=https://hooks.slack.com/services/DDD/EEE/FFF
DANGER_SLACK=https://hooks.slack.com/services/GGG/HHH/III
```

### 정책 생성
**mailer.yaml, enforce-policies.yaml 포함 정책 생성**
- 최초 1회 필수 실행
```console
generate
```

**명령어 예시**
```console
# 모든 서비스에 대해 정책 생성
generate all

# 하나의 서비스에 대해 정책 생성/모든 서비스는 띄어쓰기 없이 작성
generate apigateway

# 여러 서비스에 대해 정책 생성
generate ec2 s3
```

---

### 수동 조치 방법
> `enforce-policies.yaml`은 즉각 수동 조치를 할 수 있는 정책 파일입니다. `enforce`명령어로 특정 정책이름(CHECKID)에 대해 즉각 조치를 취할 수 있습니다. 여러 개의 정책이름 입력도 가능합니다.

**모든 정책에 대해 즉각 조치**
- 정책이 람다 배포가 되더라도 기존 AWS 리소스에 대해 이벤트가 탐지되지 않아 자동 조치가 이루어지지 않을 수 있습니다. 따라서 최초 1회 실행을 권장합니다.
```console
enforce
# 또는
enforce all
```

**`mailer` 실행**
- 정책을 실행하고 `y`를 입력해 `mailer`를 실행할 수 있습니다.
```console
(custodian) $ enforce ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23
▶ Running: custodian run --region ap-northeast-2 -s /home/user/isms-p-aws-custodian/out -p ec2_securitygroup_allow /home/user/isms-p-aws-custodian/enforce/enforce-policies.yaml
2025-07-31 16:54:05,144: custodian.policy:INFO policy:ec2_securitygroup_allow resource:aws.security-group region:ap-northeast-2 count:0 time:0.00
🎉 Custodian run completed successfully!
Would you like to run the mailer (c7n-mailer)? [y/N]:
```
**명령어 예시**
```console
# 특정 CHECKID에 대해 조치
enforce ec2_ebs_default_encryption

# CHECKID를 여러개 입력하는 것도 가능합니다
enforce ec2_ebs_default_encryption vpc_flow_logs_enabled

# 다음과 같이 입력하는 것도 가능합니다
enforce ec2*

# 실제 Cloud Custodian의 flag를 입력하여 전달할 수 있습니다
enforce -s . ec2_ebs* vpc_flow_logs_enabled
enforce --dryrun -s out s3*

# 정책이 잘 탐지되지 않을 경우 cache를 비우면서 실행해 보세요.
enforce --cache-period=0 -s out elb* 
```

### 정책 람다 배포
> `deploy` 명령어를 입력하여 정책을 람다 배포하여 조치를 자동화 할 수 있습니다.

**`mailer`배포**
- 최초 1회 필수 실행
```console
deploy mailer
```
**명령어 예시**
```console
# 존재하는 모든 정책 배포
deploy
# 또는
deploy all

# 특정 CHECKID에 대해 배포
deploy ec2_ebs_default_encryption

# CHECKID를 여러개 입력하는 것도 가능합니다
deploy ec2_ebs_default_encryption vpc_flow_logs_enabled

# 다음과 같이 입력하는 것도 가능합니다
deploy ec2*

# 실제 Cloud Custodian의 flag를 입력하여 전달할 수 있습니다
deploy -s . ec2_ebs* vpc_flow_logs_enabled
deploy --dryrun -s out s3*

```
</br>

## ☁️ 프로젝트 팀 - **구름수비대**

### 🙂 PM  
- [이찬휘](https://github.com/iChanee)

### 🛠️ 기술팀   
- [나영민](https://github.com/skdudals99)  
- [이다솔](https://github.com/dasol729)  
- [손예은](https://github.com/ye-nni)  
- [김진호](https://github.com/oscarjhk)  
- [송채영](https://github.com/buddle031)

### 📚 정책팀 
- [옥재은](https://github.com/Jaen-923)
- [김건희](https://github.com/ghkim583)  

---

