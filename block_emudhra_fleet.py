#!/usr/bin/env python3
"""Apply the RHEL eMudhra root blocklist via GCP SSH, AWS SSM or Azure Run Command.

Requires Python 3 and an authenticated gcloud, AWS CLI v2 or Azure CLI.
GCP: IAP SSH access and passwordless sudo on each running VM.
AWS: EC2 discovery, SSM SendCommand/GetCommandInvocation permissions,
     and SSM Agent connectivity on each running Linux instance.
Azure: Microsoft.Compute/virtualMachines/runCommand/action and a healthy
       VM agent on each running Linux VM. Scale set instances are not patched.
Only RHEL/Fedora/CentOS/Rocky/AlmaLinux and Amazon Linux 2023 are supported.
Stopped instances, Windows, containers and application CA bundles are not patched.
No cloud resource is changed until this script is explicitly run.
"""

import argparse
import base64
import gzip
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
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
for executable in trust update-ca-trust openssl curl install base64 tar gzip; do
  command -v "$executable" >/dev/null || { echo "MISSING: $executable" >&2; exit 1; }
done
# Source: https://emudhra.we-have-a-problem.com/#linux
blockdir=/etc/pki/ca-trust/source/blocklist
[ -d "$blockdir" ] || blockdir=/etc/pki/ca-trust/source/blacklist
[ -d "$blockdir" ] || { echo 'ERROR: no system blocklist directory' >&2; exit 1; }
workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT
printf '%s' '@CHAINS_ARCHIVE_BASE64@' | base64 -d > "$workdir/chains.tgz"
tar -xzf "$workdir/chains.tgz" -C "$workdir"
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
echo 'System trust rebuilt; checking ordinary HTTPS validation.'
curl -q --cacert /etc/pki/tls/certs/ca-bundle.crt --connect-timeout 10 --max-time 20 \
  -fsS -o /dev/null https://example.com/
verification_failed=0
for chain in "$workdir"/chains/*.pem; do
  rc=0
  openssl verify -no-CApath -CAfile /etc/pki/tls/certs/ca-bundle.crt \
    -untrusted "$chain" "$chain" > "$workdir/verify.log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] && grep -Eq 'error (20|21|27) at [0-9]+ depth lookup' "$workdir/verify.log"; then
    echo "PASS: original chain rejected offline: ${chain##*/}"
  else
    echo "FAIL/INCONCLUSIVE: ${chain##*/} openssl exit=$rc" >&2
    cat "$workdir/verify.log" >&2
    verification_failed=1
  fi
done
exit "$verification_failed"
'''


def build_payload():
    """Carry original public chains to the host so TLS proxies cannot mask trust."""
    chain_dir = pathlib.Path(__file__).resolve().parent / "chains"
    expected = {f"{kind}-{generation}{suffix}-emudhra.we-have-a-problem.com.pem"
                for kind in ("dv", "ev", "ov") for generation in ("g3b", "g3c")
                for suffix in ("", "-aaa")}
    if {path.name for path in chain_dir.glob("*.pem")} != expected:
        raise RuntimeError("Expected all 12 original public chain fixtures in the chains directory")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name in sorted(expected):
            contents = (chain_dir / name).read_bytes()
            info = tarfile.TarInfo("chains/" + name)
            info.size = len(contents)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(contents))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as stream:
        stream.write(raw.getvalue())
    encoded = base64.b64encode(compressed.getvalue()).decode("ascii")
    return ROOT_SCRIPT.replace("@CHAINS_ARCHIVE_BASE64@", encoded)


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
    azure = sub.add_parser("azure", help="Apply to running Linux VMs in one subscription via Run Command")
    azure.add_argument("--subscription", required=True)
    azure.add_argument("--resource-group", help="Limit to one resource group")
    args = parser.parse_args()
    payload = build_payload()
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
                              "--command=sudo -n bash -s", "--", "-T", "-o", "ConnectTimeout=15"], payload)
                report("passed", target, output)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                report("failed", target, str(exc))
    elif args.provider == "azure":
        base = ["az", "--only-show-errors", "--output", "json"]
        account = cli_json(base + ["account", "show", "--subscription", args.subscription])
        print(f"Azure subscription: {account['name']} ({account['id']}), cloud: {account.get('environmentName')}", flush=True)
        listing = base + ["vm", "list", "--show-details", "--subscription", args.subscription]
        if args.resource_group:
            listing += ["--resource-group", args.resource_group]
        # Run Command reports success whenever the extension ran, so the exit code travels in stdout.
        wrapped = ("rc=0; bash -s <<'EMUDHRA_PAYLOAD' || rc=$?\n" + payload
                   + "\nEMUDHRA_PAYLOAD\necho \"EMUDHRA_EXIT=$rc\"\n")
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as script_file:
            script_file.write(wrapped)
        try:
            for vm in cli_json(listing):
                target = f"{vm['resourceGroup']}/{vm['name']}"
                os_type = vm["storageProfile"]["osDisk"].get("osType")
                if vm.get("powerState") != "VM running" or os_type != "Linux":
                    report("skipped", target, f"State: {vm.get('powerState')}; platform: {os_type}")
                    continue
                print(f"APPLYING: {target}", flush=True)
                try:
                    result = json.loads(cli(base + ["vm", "run-command", "invoke", "--subscription", args.subscription,
                                                    "--resource-group", vm["resourceGroup"], "--name", vm["name"],
                                                    "--command-id", "RunShellScript",
                                                    "--scripts", "@" + script_file.name], timeout=900))
                    detail = "\n".join(item.get("message", "") for item in result.get("value", []))
                    passed = "EMUDHRA_EXIT=0" in detail
                    report("passed" if passed else "failed", target, detail)
                except (RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
                    report("failed", target, str(exc))
        finally:
            os.unlink(script_file.name)
    else:
        base = ["aws", "--profile", args.profile, "--no-cli-pager", "--output", "json"]
        identity = cli_json(base + ["--region", args.discovery_region, "sts", "get-caller-identity"])
        print(f"AWS account: {identity['Account']}", flush=True)
        regions = cli_json(base + ["--region", args.discovery_region, "ec2", "describe-regions"])["Regions"]
        parameters = {"commands": ["bash -s <<'EMUDHRA_PAYLOAD'\n" + payload + "\nEMUDHRA_PAYLOAD"],
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
