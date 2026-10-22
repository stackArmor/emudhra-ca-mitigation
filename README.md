# eMudhra CA fleet mitigation

Block the two parent root certificates associated with the compromised eMudhra
intermediate CAs on RHEL-family virtual machines. The Python script inventories
one GCP project or one AWS account and applies the Linux mitigation sequentially
to running hosts.

The payload follows the [incident site's RHEL instructions](https://emudhra.we-have-a-problem.com/#linux).
[Red Hat's advisory](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012)
identifies these two parent roots as mitigation targets:

- Comodo AAA Services root
- emSign ECC Root CA - G3

Blocking a parent root also rejects legitimate certificates chaining through it.
This is a system trust-store mitigation; it does not update containers, machine
images, or application-specific CA bundles. Long-running applications may cache
trust and require a restart. The script does not restart services.

## Requirements

- Python 3.7 or later, with no additional Python packages.
- GCP: authenticated `gcloud`, project inventory permissions, SSH access through
  IAP, and passwordless `sudo` on each VM. Existing OS Login/SSH policy applies.
- AWS: authenticated AWS CLI v2 profile, permission to inventory enabled regions
  and EC2 instances, and permission to send and inspect SSM Run Commands.
  Each target requires a working SSM Agent, instance IAM permissions, and SSM
  connectivity. `AWS-RunShellScript` runs the payload as root on Linux.
- Hosts: RHEL, Fedora, CentOS, Rocky Linux, AlmaLinux, or Amazon Linux 2023,
  with `trust`, `update-ca-trust`, `openssl`, `curl`, and `install` available.
- HTTPS connectivity to `example.com` and the incident site's two CLI test hosts.

## GCP

```bash
git clone https://github.com/stackArmor/emudhra-ca-mitigation.git
cd emudhra-ca-mitigation
python3 block_emudhra_fleet.py gcp --project PROJECT_ID
```

The script inventories every zone in the project and uses `gcloud compute ssh`
with IAP to stream the root payload to each running VM. Unsupported systems or
SSH failures are reported as failures. Non-running VMs are reported as skipped.

## AWS

```bash
python3 block_emudhra_fleet.py aws --profile AWS_PROFILE
```

The script prints the account ID and enumerates all enabled regions in the
selected account's partition. Each running Linux/UNIX EC2 instance receives its
own SSM command; the script waits for and reports its result. Instances without
working SSM access are reported as failures. Windows and non-running instances
are reported as skipped. Regional inventory errors are reported as failures.

For GovCloud, select a discovery endpoint in that partition:

```bash
python3 block_emudhra_fleet.py aws --profile AWS_PROFILE \
  --discovery-region us-gov-west-1
```

## What changes on each supported host

1. Find `/etc/pki/ca-trust/source/blocklist`, falling back to `blacklist`.
2. Export the matching root certificates from the host's existing trust store.
3. Install `Comodo_AAA_Services_root.pem` and `emSign_ECC_Root_CA_-_G3.pem`
   into that directory when the matching certificates exist.
4. Run `update-ca-trust` to rebuild the generated system trust stores.
5. Confirm ordinary HTTPS validation succeeds against `example.com`.
6. Require both incident test endpoints to fail with curl certificate error 60.
   Successful connections, DNS errors, timeouts, and other errors do not pass.

The test endpoints are:

- `https://dv-g3b-emudhra.we-have-a-problem.com/`
- `https://dv-g3b-aaa-emudhra.we-have-a-problem.com/`

A PASS establishes the tested curl behavior; it is not proof of every
application's effective trust policy. TLS interception or unrelated certificate
errors can affect the online checks. The script explicitly selects the generated
system CA bundle and disables curl's automatic configuration-file loading.

The script can be run again. It leaves installed blocklist files in place if
verification fails, so a verification error does not automatically restore trust.
Interrupted or partially failed runs can leave some hosts modified. For AWS,
record the printed SSM command IDs: a local interruption or timeout does not
cancel an accepted command, and it might still execute.

## Results

Each host is reported as PASSED, FAILED, or SKIPPED, followed by a summary.
Exit status 0 means every inventoried host passed. A failure or skipped host
returns nonzero and means the fleet is not fully covered. Inventory or permission
errors must be resolved before claiming account/project coverage.

Stopped VMs need remediation when started. Rebuild or update images and templates
so replacement VMs retain the mitigation. Install vendor trust-store updates as
they become available, and address independent application CA stores separately.

## Removing this mitigation

Removing the files can restore trust in compromised chains. Only remove this
temporary blocklist after confirming that vendor updates or another effective
policy rejects those chains. On each host, remove only the files created by this
script from its selected blocklist directory and run `update-ca-trust` again.
Recheck both incident test endpoints afterward.

## Validation

The script and embedded Bash payload can be syntax checked without cloud access:

```bash
python3 - <<'PY'
import ast
import pathlib
import subprocess

path = pathlib.Path('block_emudhra_fleet.py')
source = path.read_text()
tree = ast.parse(source)
compile(source, str(path), 'exec')
assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name)
                          and target.id == 'ROOT_SCRIPT'
                          for target in node.targets))
payload = ast.literal_eval(assignment.value)
subprocess.run(['bash', '-n'], input=payload, text=True, check=True)
print('Python and Bash syntax OK')
PY
```

Cloud dispatch and verification must also be assessed from actual per-host output.

## Nessus detection

The `nessus/` directory contains custom compliance audit files for detecting
hosts that still trust the compromised intermediates. Upload them as custom
audits in a Policy Compliance scan (agent or credentialed).

- `emudhra_compromised_ca_unix.audit`: fails if the system OpenSSL CA bundle
  still contains emSign Root TLS CA - G3, emSign Root CS CA - G3, emSign ECC
  Root CA - G3, or AAA Certificate Services (matched by SHA-256 fingerprint).
  Hosts mitigated by `block_emudhra_fleet.py` pass, because blocklisted roots
  are removed from the generated bundle.
- `emudhra_compromised_ca_windows.audit`: fails unless all 16 compromised
  intermediates and Sectigo cross-signs are in `LocalMachine\Disallowed`.

Both checks are offline and report the remediation commands and incident site
link in the scan results. They do not inspect application-specific CA bundles.

## References

- [Incident report and mitigation](https://emudhra.we-have-a-problem.com/)
- [Red Hat security bulletin](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012)
- [GCP SSH command reference](https://docs.cloud.google.com/sdk/gcloud/reference/compute/ssh)
- [AWS Systems Manager Run Command setup](https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command-setting-up.html)
