# IMDS Inspector

**Find EC2 instances that still allow IMDSv1 (token-optional) — the SSRF credential-theft vector.**

IMDSv1 lets any process that can reach `169.254.169.254` read the instance's IAM role credentials
with a plain GET — no session token. An SSRF bug in an app then becomes credential theft. IMDSv2
(`HttpTokens=required`) requires a PUT-issued token and a hop limit, closing the vector. This
read-only tool flags live instances whose metadata service still accepts v1 and scores each by
blast radius.

## Domain
Security

## Usage
```bash
python imds_inspector.py [--profile P] [--region R] [--format text|json] [--fail-on SEVERITY]
```

Examples:
```bash
python imds_inspector.py --region us-east-1
python imds_inspector.py --region us-east-1 --fail-on HIGH   # CI gate
python imds_inspector.py --format json | jq '.findings[]'
```

## Severity model (blast-radius scored)

An instance is flagged (`IMDSV1_ALLOWED`) when the metadata endpoint is **enabled** and
`HttpTokens=optional`. Severity then depends on what an attacker could reach:

| IAM role attached | Public IP | Severity | Why |
|:--:|:--:|:--:|-----|
| ✔ | ✔ | **CRITICAL** | Internet-facing app + harvestable role credentials |
| ✔ | ✘ | **HIGH** | Role creds reachable via SSRF from inside the VPC |
| ✘ | ✔ | **MEDIUM** | Publicly reachable, but no role creds to steal yet |
| ✘ | ✘ | **LOW** | Internal, no role — latent risk if a role is later attached |

Instances not in a live state (`terminated`/`shutting-down`) are skipped. An instance with no
`MetadataOptions` is treated as v1-allowed (that's the AWS default for older launches).

`--fail-on SEVERITY` → **exit code 3** when any finding meets/exceeds the threshold (CI gating).

## Remediation (emitted, not executed)
Each finding includes a copy-paste fix; the tool never mutates live state:
```bash
aws ec2 modify-instance-metadata-options --instance-id <id> \
  --http-tokens required --http-endpoint enabled
```
For IaC, set `metadata_options { http_tokens = "required" }` on the launch template / instance.

## Seeded finding it catches in the lab
- `legacy` instance — `http_tokens = "optional"` in a private subnet, no public IP. With the
  app SG (no instance profile in the lab) it reports **LOW**; attach a role and it escalates.
- The `app` launch template, `bastion`, and `oversized` instances all enforce IMDSv2, so they are
  correctly **not** flagged (signal-vs-noise check).

## Required IAM permissions
```
ec2:DescribeInstances
```
(`ec2:ModifyInstanceMetadataOptions` only if you run the emitted remediation yourself.)

## Limitations
- Single region per run; loop over `--region` for an account-wide sweep.
- Detects launched instances only. A launch template defaulting to IMDSv1 is invisible until it
  launches an instance — pair with `tf-plan-guard` to catch it pre-apply.
- A high hop limit (`HttpPutResponseHopLimit > 1`) with v2 enabled is a container-escape nuance
  this tool reports in JSON (`hop_limit`) but does not independently flag.
- Severity is judged purely from each instance's own `MetadataOptions`. It does not account for
  the **account-level / regional IMDS defaults** (`ec2:GetInstanceMetadataDefaults`) introduced in
  2024, which can enforce IMDSv2 even when an instance's own setting reads `optional`. On accounts
  that have set those defaults, a finding here may be a false positive — confirm with
  `aws ec2 get-instance-metadata-defaults --region <R>` before acting.
