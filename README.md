<div align="center">

# isms-p-aws-custodian 
### Prowler & CloudCustodian 기반 ISMS-P 대응 툴..?

[![화이트햇 스쿨](https://img.shields.io/badge/화이트햇_스쿨_3기-blueviolet?style=flat)]()  
[![구름수비대](https://img.shields.io/badge/구름수비대-팀-blue?style=flat&logo=cloud)]()

</div>

---


## 개요

### 목적
- 클라우드 보안 위협 증가와 수동 점검의 한계를 극복하기 위한 자동화 대응 시스템 구축
- 오픈소스를 기반으로 AWS 환경에서 ISMS-P 중심의 보안 점검 및 대응 자동화 구현

### 기능
1. 
2. 

### 공식 노션
- [AWS 보안 및 컴플라이언스 자동화 가이드](https://www.notion.so/AWS-23fc86faa56f80ce9865ffe805df09e8?source=copy_link)
- [isms-p-aws-custodian 사용 가이드](https://www.notion.so/isms-p-aws-custodian-240c86faa56f8074a5f1d0a4378d6f24?source=copy_link)
---

## 사용 방법
> Prowler, Cloud Custodian의 설치 방법은 설명하지 않습니다. Prowler, Cloud Custodian의 공식 문서 또는 구름수비대 팀 공식 노션을 참고하세요.

### isms-p-aws-custodian 설치

**Git 리포지토리 클론**
```
git clone https://github.com/WHS3-CloudGuardians/isms-p-aws-custodian.git
```
**의존성 설치**
```
# isms-p-aws-custodian 경로로 이동 후
$ pip install -e .
```

### 환경 설정
- 정책을 생성하기 전에 AWS 환경을 세팅하고 .env 파일 구성을 완료하세요. .env파일에 빈 항목이 있으면 정책이 생성되지 않습니다.

**AWS 환경 세팅용 테라폼 배포 (선택 사항)**
```
# 더 추가 예정
terraform init
terraform plan
terraform apply
```
**`.env` 파일 구성**
```
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

