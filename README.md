# AWS Terraform Lab + EC2 Toolkit

A Terraform-provisioned EC2 environment plus a suite of standalone analyzers that audit it —
built as hands-on study for the **Solutions Architect Associate (SAA-C03)**, **SysOps
Administrator (SOA-C02)**, and **Security Specialty (SCS)** certifications.

> **Status: ALL TOOLS IMPLEMENTED.** The Terraform lab is fully built and `terraform validate`-clean
> (network + compute + alb modules, with the intentional findings seeded and clearly labeled). All
> seven analyzers — **sg-auditor**, **imds-inspector**, **right-sizer**, **network-reachability**,
> **tf-plan-guard**, **ebs-hygiene**, and **resilience-checker** — are implemented with fake-boto3
> unit tests (113 passing) and filled-out READMEs. `make check` is green (ruff + compile + pytest +
> terraform validate).

---

## Vision

Two halves that reinforce each other:

1. **`terraform/`** — a realistic, intentionally-imperfect multi-tier EC2 environment (VPC, ALB,
   Auto Scaling Group, bastion, a few standalone instances). It is both your IaC practice and the
   *proving ground* the analyzers run against. It deliberately seeds findings (an SG open to the
   world, an unencrypted volume, an IMDSv1 instance, a single-AZ ASG) so every tool has something
   real to detect.

2. **The analyzer tools** — focused, mostly read-only CLIs (Python + boto3), each self-contained
   in its own directory with its own README and `requirements.txt`. Same design as the companion
   `aws-iam` toolkit.

---

## Tools

All seven are implemented, each with fake-boto3 unit tests and a filled-out README.

| Tool | What it does | Primary cert domain | Status |
|------|--------------|---------------------|:--:|
| [**sg-auditor**](sg-auditor/) | Flags `0.0.0.0/0` on sensitive ports (22/3389/db), unused SGs, redundant/over-broad rules; maps SG → ENI usage | Security | ✅ |
| [**imds-inspector**](imds-inspector/) | Finds instances allowing IMDSv1 (token-optional) — the SSRF vector — and emits remediation | Security (SOA/SCS) | ✅ |
| [**right-sizer**](right-sizer/) | CloudWatch utilization → over-provisioned instances; recommends smaller types / Graviton; estimates savings | Cost (SAA) | ✅ |
| [**ebs-hygiene**](ebs-hygiene/) | Unattached/unencrypted volumes, snapshot coverage gaps, orphaned/old snapshots | Cost + resilience | ✅ |
| [**resilience-checker**](resilience-checker/) | Single-AZ ASGs, missing health checks, AZ spread, ALB target health | Reliability (SAA) | ✅ |
| [**network-reachability**](network-reachability/) | "What can reach this instance?" — composes SG + NACL + route table + public IP into an exposure verdict | Security + Networking | ✅ (showpiece) |
| [**tf-plan-guard**](tf-plan-guard/) | Parses `terraform show -json` and fails CI on risky EC2/SG changes *before apply* | IaC + Security | ✅ |

---

## Design conventions (carried from the `aws-iam` toolkit)

These are non-negotiable so the suite stays coherent. Apply them to every tool:

- **Standalone by intent.** Each tool is a single script in its own directory with its own
  `requirements.txt` and README. **No shared import module** — copy-one-folder-and-run portability
  is worth the small duplication (retry config, pagination helpers, `_ensure_list`).
- **Read-only by default.** Only explicit remediation actions mutate AWS, and they should prefer
  *emitting* Terraform / CLI commands over making live changes. Flag any mutation clearly.
- **Severity model + CI gating.** Findings carry `LOW/MEDIUM/HIGH/CRITICAL`. Provide
  `--fail-on <severity>` that returns **exit code 3** when findings meet the threshold (other
  non-zero = error, 0 = clean). This is what makes them usable in pipelines.
- **Output modes.** `--format text` (default, human) and `--format json` (automation).
- **Robustness.** Adaptive-retry botocore `Config(retries={"mode": "adaptive", "max_attempts": 10})`
  on every client; paginate **all** `describe_*` calls via `get_paginator`.
- **Testing.** Unit tests (`test_<module>.py`) using **fake boto3 clients** (no live AWS). Test the
  pure classification/logic, not the API plumbing. Aim to keep CI fully offline-runnable.
- **CLI shape.** `argparse` with subcommands where it helps; global `--profile`, `--region`,
  `--format`. Default region handling: EC2 is regional, so region matters (unlike IAM).

### Terraform conventions
- Terraform 1.5+, AWS provider `~> 5.0`. Pin in `terraform/versions.tf`.
- Modules under `terraform/modules/`, root composition in `terraform/main.tf`.
- **Never commit state or secrets.** `.tfstate`, `.tfvars` (except `*.example`), and `.terraform/`
  are git-ignored. Commit the `.terraform.lock.hcl`.
- CI runs `terraform fmt -check`, `terraform validate`, and `tflint` alongside the Python checks.

---

## Repo layout

```
aws-terraform-lab/
├── README.md                  # this file
├── .gitignore                 # Python + Terraform + secrets hardened
├── Makefile                   # install / test / lint / compile / tf-validate / check
├── pyproject.toml             # ruff + pytest config
├── requirements-dev.txt       # pytest, ruff, boto3
├── .github/workflows/ci.yml   # Python lint+test + Terraform fmt/validate
├── terraform/                 # the EC2 lab (proving ground + IaC practice)
│   ├── README.md              # what it provisions + seeded findings
│   ├── versions.tf            # pinned terraform + provider versions
│   ├── providers.tf           # AWS provider + default tags
│   ├── variables.tf           # inputs (region, cidr, az_count, key_name, ...)
│   ├── main.tf                # root composition (wires network → compute → alb)
│   ├── outputs.tf             # vpc/subnets, alb_dns_name, seeded_findings map
│   └── modules/               # network, compute (seeds findings), alb
└── <tool>/                    # one directory per analyzer (see table above)
    ├── README.md              # purpose, usage, severity model, IAM perms, limitations
    ├── requirements.txt       # boto3/botocore pinned (tf-plan-guard: stdlib only)
    ├── <tool>.py              # implementation
    └── test_<tool>.py         # fake-boto3 unit tests
```

---

## How to use

1. **Set up the dev environment** (offline-runnable, no AWS needed):
   ```bash
   python3 -m venv .venv && . .venv/bin/activate
   pip install -r requirements-dev.txt
   make check          # ruff + compile + pytest (+ terraform validate if terraform present)
   ```
2. **Run a single tool's tests:** `python -m pytest sg-auditor/ -q`
3. **Run an analyzer against a live account** (read-only):
   ```bash
   python sg-auditor/sg_auditor.py --region us-east-1 --fail-on HIGH
   ```
4. **Stand up the proving ground** to see every tool light up (billable — sandbox account only):
   ```bash
   cd terraform && terraform init && terraform apply -var="key_name=my-keypair"
   # ...run the analyzers (see terraform/README.md), then:
   terraform destroy -var="key_name=my-keypair"
   ```

The Terraform lab seeds one or more findings for each analyzer on purpose — see
`terraform/README.md` for the catalogue mapping each seeded misconfiguration to the tool that
detects it.

**Reference implementation:** the sibling `aws-iam` toolkit (`../aws-iam`) is the pattern this
suite follows for tool structure, severity/`--fail-on`, retry/pagination, and fake-client tests.

---

## Requirements

- Python 3.9+, `boto3`/`botocore` (per-tool `requirements.txt`)
- Terraform 1.5+, AWS provider ~> 5.0
- AWS credentials with EC2/CloudWatch **read** permissions (each tool's README will list specifics;
  remediation features need the corresponding write actions)

## Cost warning

The Terraform lab provisions billable resources (NAT gateway(s), ALB, EC2 instances). Use a
sandbox account, `terraform destroy` when done, and consider a budget alarm.
