#!/usr/bin/env python3
"""Apply the RHEL eMudhra root blocklist via GCP SSH or AWS SSM.

Requires Python 3 and an authenticated gcloud or AWS CLI v2.
GCP: IAP SSH access and passwordless sudo on each running VM.
AWS: EC2 discovery, SSM SendCommand/GetCommandInvocation permissions,
     and SSM Agent connectivity on each running Linux instance.
Only RHEL/Fedora/CentOS/Rocky/AlmaLinux and Amazon Linux 2023 are supported.
Stopped instances, Windows, containers and application CA bundles are not patched.
No cloud resource is changed until this script is explicitly run.
"""

import argparse
import json
import subprocess
import sys
import time


ROOT_SCRIPT = r'''#!/usr/bin/env bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo 'ERROR: root required' >&2; exit 1; }
. /etc/os-release
case "${ID:-}" in
  rhel|centos|rocky|almalinux|fedora) ;;
  amzn) [ "${VERSION_ID:-}" = 2023 ] || { echo 'UNSUPPORTED: Amazon Linux version' >&2; exit 2; } ;;
  *) echo "UNSUPPORTED OS: ${ID:-unknown}" >&2; exit 2 ;;
esac
for executable in trust update-ca-trust openssl curl install; do
  command -v "$executable" >/dev/null || { echo "MISSING: $executable" >&2; exit 1; }
done
# Source: https://emudhra.we-have-a-problem.com/#linux
blockdir=/etc/pki/ca-trust/source/blocklist
[ -d "$blockdir" ] || blockdir=/etc/pki/ca-trust/source/blacklist
[ -d "$blockdir" ] || { echo 'ERROR: no system blocklist directory' >&2; exit 1; }
workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT
for label in 'Comodo%20AAA%20Services%20root' 'emSign%20ECC%20Root%20CA%20-%20G3'; do
  case "$label" in
    Comodo*) filename=Comodo_AAA_Services_root.pem ;;
    *) filename=emSign_ECC_Root_CA_-_G3.pem ;;
  esac
  trust extract --overwrite --format=pem-bundle \
    --filter="pkcs11:object=$label;type=cert" "$workdir/$filename"
  if [ -s "$workdir/$filename" ]; then
    openssl x509 -in "$workdir/$filename" -noout -subject
    install -m 0644 "$workdir/$filename" "$blockdir/$filename"
  else
    echo "Root not present: $label"
  fi
done
update-ca-trust
echo 'System trust rebuilt; checking HTTPS validation.'
curl -q --cacert /etc/pki/tls/certs/ca-bundle.crt --connect-timeout 10 --max-time 20 \
  -fsS -o /dev/null https://example.com/
verification_failed=0
for host in dv-g3b-emudhra.we-have-a-problem.com dv-g3b-aaa-emudhra.we-have-a-problem.com; do
  rc=0
  curl -q --cacert /etc/pki/tls/certs/ca-bundle.crt --connect-timeout 10 --max-time 20 \
    -sS -o /dev/null "https://$host/" || rc=$?
  if [ "$rc" -eq 60 ]; then
    echo "PASS: certificate rejected: $host"
  else
    echo "FAIL/INCONCLUSIVE: $host curl exit=$rc" >&2
    verification_failed=1
  fi
done
exit "$verification_failed"
'''


def cli(argv, payload=None, timeout=240):
    result = subprocess.run(argv, input=payload, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Exit {result.returncode}\n{result.stdout}\n{result.stderr}".strip())
    return result.stdout


def cli_json(argv):
    return json.loads(cli(argv))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="provider", required=True)
    gcp = sub.add_parser("gcp", help="Apply to running VMs across all zones in one project")
    gcp.add_argument("--project", required=True)
    aws = sub.add_parser("aws", help="Apply to running Linux EC2 VMs across enabled regions")
    aws.add_argument("--profile", required=True)
    aws.add_argument("--discovery-region", default="us-east-1", help="Use us-gov-west-1 for GovCloud")
    args = parser.parse_args()
    counts = {"passed": 0, "failed": 0, "skipped": 0}

    def report(kind, target, detail=""):
        counts[kind] += 1
        print(f"{kind.upper()}: {target}", flush=True)
        if detail:
            print(detail, flush=True)

    if args.provider == "gcp":
        instances = cli_json(["gcloud", "compute", "instances", "list", "--project", args.project, "--format=json"])
        for instance in instances:
            zone = instance["zone"].rsplit("/", 1)[-1]
            target = f"{args.project}/{zone}/{instance['name']}"
            if instance["status"] != "RUNNING":
                report("skipped", target, f"State: {instance['status']}")
                continue
            print(f"APPLYING: {target}", flush=True)
            try:
                output = cli(["gcloud", "compute", "ssh", instance["name"], "--project", args.project,
                              "--zone", zone, "--tunnel-through-iap", "--quiet",
                              "--command=sudo -n bash -s", "--", "-T", "-o", "ConnectTimeout=15"], ROOT_SCRIPT)
                report("passed", target, output)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                report("failed", target, str(exc))
    else:
        base = ["aws", "--profile", args.profile, "--no-cli-pager", "--output", "json"]
        identity = cli_json(base + ["--region", args.discovery_region, "sts", "get-caller-identity"])
        print(f"AWS account: {identity['Account']}", flush=True)
        regions = cli_json(base + ["--region", args.discovery_region, "ec2", "describe-regions"])["Regions"]
        parameters = {"commands": ["bash -s <<'EMUDHRA_PAYLOAD'\n" + ROOT_SCRIPT + "\nEMUDHRA_PAYLOAD"],
                      "executionTimeout": ["180"]}
        for region in sorted(item["RegionName"] for item in regions):
            regional = base + ["--region", region]
            try:
                inventory = cli_json(regional + ["ec2", "describe-instances"])
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                report("failed", region + " INVENTORY", str(exc))
                continue
            instances = [i for r in inventory["Reservations"] for i in r["Instances"]]
            for instance in instances:
                target = f"{region}/{instance['InstanceId']}"
                if instance["State"]["Name"] != "running" or instance.get("Platform") == "windows":
                    report("skipped", target, f"State: {instance['State']['Name']}; platform: {instance.get('Platform', 'Linux/UNIX')}")
                    continue
                print(f"APPLYING: {target}", flush=True)
                try:
                    sent = cli_json(regional + ["ssm", "send-command", "--document-name", "AWS-RunShellScript",
                                               "--instance-ids", instance["InstanceId"], "--timeout-seconds", "60",
                                               "--parameters", json.dumps(parameters),
                                               "--comment", "Block eMudhra parent roots and verify TLS rejection"])
                    command_id = sent["Command"]["CommandId"]
                    print(f"SSM command: {command_id}", flush=True)
                    deadline = time.monotonic() + 360
                    while time.monotonic() < deadline:
                        time.sleep(5)
                        try:
                            result = cli_json(regional + ["ssm", "get-command-invocation", "--command-id", command_id,
                                                         "--instance-id", instance["InstanceId"]])
                        except RuntimeError as exc:
                            if "InvocationDoesNotExist" in str(exc):
                                continue
                            raise
                        if result["Status"] in ("Pending", "InProgress", "Delayed", "Cancelling"):
                            continue
                        detail = result.get("StandardOutputContent", "") + result.get("StandardErrorContent", "")
                        passed = result["Status"] == "Success" and result.get("ResponseCode") == 0
                        report("passed" if passed else "failed", target, f"SSM status: {result['Status']}\n{detail}")
                        break
                    else:
                        report("failed", target, f"Status unresolved; inspect SSM command {command_id}. It may still execute.")
                except (RuntimeError, subprocess.TimeoutExpired) as exc:
                    report("failed", target, str(exc))
    print("SUMMARY: " + json.dumps(counts), flush=True)
    print("Skipped/failed hosts remain uncovered. Containers and independent application CA stores are outside this rollout.")
    return 1 if counts["failed"] or counts["skipped"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
