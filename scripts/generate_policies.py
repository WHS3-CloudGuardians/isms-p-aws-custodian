#!/usr/bin/env python3
import os
import sys
import glob
import subprocess
from dotenv import load_dotenv

# 지원되는 서비스 이름 매핑 (소문자)
ALIAS_MAP = {
    # Load Balancer
    'elbv2': 'elb',
    'alb': 'elbv2',
}

REQUIRED_ENVS = [
    'ACCOUNT_ID',
    'AWS_REGION',
    'LAMBDA_ROLE',
    'MAILER_ROLE',
    'QUEUE_URL',
    'GOOD_SLACK',
    'WARNING_SLACK',
    'DANGER_SLACK',
]


def usage():
    cmd = os.path.basename(sys.argv[0])
    print(f"Usage: {cmd} [<resource> ...] | all", file=sys.stderr)
    print("  service: name or alias of a folder under templates/")
    print("  all     : generate for all resources in templates/")
    sys.exit(1)


def main():
    # 경로 설정
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.abspath(os.path.join(script_dir, '..'))
    templates_dir = os.path.join(root, 'templates')
    policies_dir  = os.path.join(root, 'policies')
    enforce_dir   = os.path.join(root, 'enforce')
    mailer_dir    = os.path.join(root, 'mailer')
    env_file      = os.path.join(root, '.env')

    # .env 로드 및 검증
    if not os.path.isfile(env_file):
        print(f"Error: .env not found at {env_file}", file=sys.stderr)
        sys.exit(1)
    load_dotenv(env_file)
    missing = [v for v in REQUIRED_ENVS if not os.getenv(v)]
    if missing:
        print("Error: The following environment variables are missing or empty in .env:", file=sys.stderr)
        for var in missing:
            print(f"  - {var}", file=sys.stderr)
        sys.exit(1)

    # 인자 파싱
    args = sys.argv[1:]
    if len(args) == 0:
        # enforce-policies.yaml 생성
        os.makedirs(enforce_dir, exist_ok=True)
        tpl_ep = os.path.join(templates_dir, 'enforce-policies.yaml.template')
        out_ep = os.path.join(enforce_dir, 'enforce-policies.yaml')
        print(f"▶ Generating {out_ep}")
        with open(tpl_ep) as src, open(out_ep, 'w') as dst:
            subprocess.run(['envsubst'], input=src.read(), text=True, stdout=dst)

        # mailer.yaml 생성
        os.makedirs(mailer_dir, exist_ok=True)
        tpl_m = os.path.join(templates_dir, 'mailer.yaml.template')
        out_m = os.path.join(mailer_dir, 'mailer.yaml')
        print(f"▶ Generating {out_m}")
        with open(tpl_m) as src, open(out_m, 'w') as dst:
            subprocess.run(['envsubst'], input=src.read(), text=True, stdout=dst)
        print()

        selection = input("Enter services to process (e.g. ec2 elb) or all: ").split()
        if not selection:
            usage()
        if selection[0].lower() == 'all':
            to_process = [d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))]
        else:
            to_process = []
            all_res = [d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))]
            for res in selection:
                key = res.lower()
                canonical = ALIAS_MAP.get(key, key)
                if canonical in all_res:
                    to_process.append(canonical)
                else:
                    print(f"Warning: service '{res}' not found (mapped to '{canonical}'), skipping", file=sys.stderr)
    else:
        if args[0].lower() == 'all':
            to_process = [d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))]
        else:
            to_process = []
            all_res = [d for d in os.listdir(templates_dir) if os.path.isdir(os.path.join(templates_dir, d))]
            for res in args:
                key = res.lower()
                canonical = ALIAS_MAP.get(key, key)
                if canonical in all_res:
                    to_process.append(canonical)
                else:
                    print(f"Warning: service '{res}' not found (mapped to '{canonical}'), skipping", file=sys.stderr)

    # 정책 생성
    for r in to_process:
        src_dir = os.path.join(templates_dir, r)
        dst_dir = os.path.join(policies_dir, r)
        if not os.path.isdir(src_dir):
            print(f"Warning: template for '{r}' not found, skipping", file=sys.stderr)
            continue
        os.makedirs(dst_dir, exist_ok=True)
        print(f"▶ Generating policies for service: {r}")
        for tpl in glob.glob(os.path.join(src_dir, '*.yaml.template')):
            name = os.path.basename(tpl).replace('.yaml.template', '.yaml')
            out = os.path.join(dst_dir, name)
            with open(tpl) as src_file, open(out, 'w') as dst_file:
                subprocess.run(['envsubst'], input=src_file.read(), text=True, stdout=dst_file)
            print(f"  - {out}")

    print("\n🎉 Generation completed.")

if __name__ == '__main__':
    main()
