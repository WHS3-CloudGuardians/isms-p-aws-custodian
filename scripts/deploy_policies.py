#!/usr/bin/env python3
import os
import sys
import subprocess
import fnmatch
from dotenv import load_dotenv

# 사용자 입력 패턴 접두사 매핑 (prefix -> 실제 정책 이름)
EXCEPTION_PREFIXES = [
    ('ec2_instance_port_', 'ec2_instance_port'),
    ('ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_', 'ec2_securitygroup_allow'),
    ('account_maintain_different_contact_details_to_security_billing_and_operations',
     'account_maintain_different_contact_details_security_bill_op'),
    # 추가 매핑 항목을 여기에 넣으세요
]

def main():
    # 1) 프로젝트 루트 및 .env 로드
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(script_dir, '..'))
    env_file = os.path.join(root, '.env')
    if not os.path.isfile(env_file):
        print(f"Error: .env not found at {env_file}", file=sys.stderr)
        sys.exit(1)
    load_dotenv(env_file)

    # 2) policies 디렉토리 및 서비스 목록
    policies_dir = os.path.join(root, 'policies')
    if not os.path.isdir(policies_dir):
        print(f"Error: policies directory not found: {policies_dir}", file=sys.stderr)
        sys.exit(1)
    services = [d for d in os.listdir(policies_dir)
                if os.path.isdir(os.path.join(policies_dir, d))]

    # 3) output-dir 및 리전 설정
    outdir = os.path.join(root, 'out')
    os.makedirs(outdir, exist_ok=True)
    region = os.getenv('AWS_REGION', 'ap-northeast-2')

    # 4) 인자 파싱: flags와 patterns 분리
    args = sys.argv[1:]
    flags = []
    idx = 0
    while idx < len(args) and args[idx].startswith('-'):
        flags.append(args[idx])
        if idx + 1 < len(args) and not args[idx+1].startswith('-'):
            flags.append(args[idx+1])
            idx += 1
        idx += 1
    patterns = args[idx:] or ['all']

    # 5) mailer 배포 처리
    if len(patterns) == 1 and patterns[0].lower() == 'mailer':
        mailer_cfg = os.path.join(root, 'mailer', 'mailer.yaml')
        if os.path.isfile(mailer_cfg):
            print(f"▶ Deploying mailer with config: {mailer_cfg}")
            rc = subprocess.run(['c7n-mailer', '-c', mailer_cfg, '--update-lambda']).returncode
            sys.exit(rc)
        else:
            print(f"Error: mailer config not found: {mailer_cfg}", file=sys.stderr)
            sys.exit(1)

    # 6) 예외 접두사 매핑 적용
    mapped = []
    for p in patterns:
        mp = p
        for prefix, target in EXCEPTION_PREFIXES:
            if mp.startswith(prefix):
                mp = target
                break
        mapped.append(mp)

    # 7) 서비스 선택
    all_mode = mapped[0].lower() == 'all'
    selected = []
    if all_mode:
        selected = services
    else:
        for pat, raw in zip(mapped, patterns):
            if '*' in raw or '?' in raw:
                matched = fnmatch.filter(services, pat)
            else:
                svc = pat.split('_', 1)[0]
                matched = [svc] if svc in services else []
            if not matched:
                print(f"Warning: no service folder matches pattern '{raw}'", file=sys.stderr)
            else:
                selected.extend(matched)
        # 중복 제거
        selected = list(dict.fromkeys(selected))

    if not selected:
        print("Error: no service policies to deploy.", file=sys.stderr)
        sys.exit(1)

    # 8) 정책 파일 경로 수집
    policy_files = []
    for svc in selected:
        svc_file = os.path.join(policies_dir, svc, f"{svc}.yaml")
        if os.path.isfile(svc_file):
            policy_files.append(svc_file)
        else:
            print(f"Warning: policy file not found for service '{svc}': {svc_file}", file=sys.stderr)

    if not policy_files:
        print("Error: no policy files to deploy.", file=sys.stderr)
        sys.exit(1)

    # 9) Custodian 실행
    cmd = ['custodian', 'run']
    if not any(f in ('-r', '--region') for f in flags):
        cmd += ['--region', region]
    if not any(f in ('-s', '--output-dir') for f in flags):
        cmd += ['-s', outdir]
    cmd += flags
    # 매핑된 패턴으로 필터 적용
    if not all_mode:
        for mp in mapped:
            cmd += ['-p', mp]
    cmd += policy_files

    print('▶ Running:', ' '.join(cmd))
    rc = subprocess.run(cmd).returncode
    if rc == 0:
        print('🎉 All specified policies deployed successfully!')
    else:
        print('❌ Deployment failed for some policies.', file=sys.stderr)
    sys.exit(rc)


if __name__ == '__main__':
    main()
