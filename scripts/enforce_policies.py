#!/usr/bin/env python3
import os
import sys
import subprocess
from dotenv import load_dotenv

# 사용자 입력 패턴 -> 실제 정책 이름 매핑
PATTERN_EXCEPTIONS = {
    # 여러 CHECKID가 하나의 정책으로 매핑
    'ec2_instance_port_sqlserver_exposed_to_internet': 'ec2_instance_port',
    'ec2_instance_port_ssh_exposed_to_internet': 'ec2_instance_port',
    'ec2_instance_port_telnet_exposed_to_internet': 'ec2_instance_port',
    # CHECKID 축약칭 매핑
    'account_maintain_different_contact_details_to_security_billing_and_operations':
        'account_maintain_different_contact_details_security_bill_op',
    # 추가 매핑은 여기에 계속 정의 가능
}

def main():
    # 1) 프로젝트 루트 및 .env 로드
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    env_file = os.path.join(root, '.env')
    if not os.path.isfile(env_file):
        print(f"Error: .env not found at {env_file}", file=sys.stderr)
        sys.exit(1)
    load_dotenv(env_file)

    # 2) 정책 파일 확인
    policy_file = os.path.join(root, 'enforce', 'enforce-policies.yaml')
    if not os.path.isfile(policy_file):
        print(f"Error: policy file not found: {policy_file}", file=sys.stderr)
        sys.exit(1)

    # 3) 출력 디렉토리 생성
    outdir = os.path.join(root, 'out')
    os.makedirs(outdir, exist_ok=True)

    # 4) 기본 리전
    region = os.getenv('AWS_REGION', 'ap-northeast-2')

    # 5) 인자 파싱: flags와 raw_patterns 분리
    args = sys.argv[1:]
    flags = []
    i = 0
    while i < len(args) and args[i].startswith('-'):
        flags.append(args[i])
        if i + 1 < len(args) and not args[i+1].startswith('-'):
            flags.append(args[i+1])
            i += 1
        i += 1
    raw_patterns = args[i:] or ['all']

    # 6) all 모드 여부
    all_mode = raw_patterns[0].lower() == 'all'

    # 7) 예외 매핑 적용
    patterns = []
    if not all_mode:
        for p in raw_patterns:
            mapped = PATTERN_EXCEPTIONS.get(p, p)
            patterns.append(mapped)

    # 8) Custodian 커맨드 조립
    cmd = ['custodian', 'run']
    if not any(f in ('-r', '--region') for f in flags):
        cmd += ['--region', region]
    if not any(f in ('-s', '--output-dir') for f in flags):
        cmd += ['-s', outdir]
    cmd += flags
    if not all_mode:
        for pat in patterns:
            cmd += ['-p', pat]
    cmd += [policy_file]

    # 9) 실행 및 요약
    print('▶ Running:', ' '.join(cmd))
    rc = subprocess.run(cmd).returncode
    if rc == 0:
        print('🎉 Custodian run completed successfully!')
    else:
        print('❌ Custodian run failed!', file=sys.stderr)
    sys.exit(rc)

if __name__ == '__main__':
    main()
