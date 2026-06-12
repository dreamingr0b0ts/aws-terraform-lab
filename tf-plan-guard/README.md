# Terraform Plan Guard

**Fail CI on risky EC2/SG changes in a Terraform plan — before `apply`.**

A pre-apply gate. It parses the JSON form of a plan (`terraform show -json plan.tfplan`) and flags
risky create/update changes so a pipeline can block them *before* anything reaches AWS. The other
tools in this suite audit what already exists; this one shifts the same checks left.

Pure standard library — **no AWS calls and no third-party dependencies** — so it runs anywhere.

## Domain
IaC + Security.

## Usage
```bash
# Produce the machine-readable plan, then guard it
terraform plan -out=plan.tfplan
terraform show -json plan.tfplan > plan.json

python tf_plan_guard.py --plan-file plan.json --fail-on HIGH
# ...or stream it straight in:
terraform show -json plan.tfplan | python tf_plan_guard.py --fail-on HIGH
```

Drop-in CI step:
```yaml
- run: terraform show -json plan.tfplan | python tf-plan-guard/tf_plan_guard.py --fail-on HIGH
```

## What it detects

| Finding | Trigger | Severity |
|---------|---------|:--------:|
| `SG_WORLD_OPEN_PORT` | SG rule opens SSH(22)/RDP(3389) to `0.0.0.0/0` or `::/0` | **CRITICAL** |
| `SG_WORLD_OPEN_PORT` | SG rule opens a DB/admin port to the world | **HIGH** |
| `SG_WORLD_OPEN_ALL_PORTS` | SG rule opens all ports/protocols to the world | **CRITICAL** |
| `SG_WORLD_OPEN_PORT` | SG rule opens a non-sensitive port to the world (web 80/443 → LOW) | **MEDIUM** / **LOW** |
| `IMDSV1_ALLOWED` | `aws_instance` / `aws_launch_template` with `http_tokens != "required"` | **HIGH** |
| `EBS_UNENCRYPTED` | `aws_ebs_volume` / root / block-device with `encrypted = false` | **HIGH** |
| `PUBLIC_IP_ASSIGNED` | `associate_public_ip_address = true` | **LOW** |

Covers both the modern `aws_vpc_security_group_ingress_rule` and the inline-block /
`aws_security_group_rule` styles. Only `create` / `update` actions are inspected — deletions and
no-ops are ignored.

`--fail-on SEVERITY` → **exit code 3** when any finding meets/exceeds the threshold (the CI gate).

## Catching the lab's seeded findings
Run it against a plan of `terraform/` and it should flag the seeded `bastion-sg` (world-open
SSH/RDP → CRITICAL), the `legacy` instance (`http_tokens="optional"` + unencrypted root → HIGH),
the orphan EBS volume (unencrypted → HIGH), and the bastion's public IP (LOW).

## Required IAM permissions
None — operates on a plan file. (Producing the plan needs whatever Terraform itself requires.)

## Limitations
- Sees only what's in the plan's `after` state. Values still "known after apply" (e.g. a computed
  CIDR) can't be evaluated and won't be flagged.
- Static rule set focused on EC2/SG/EBS/IMDS. It is not a general policy engine — pair with
  `tfsec`/`checkov`/OPA for breadth; this is the EC2-focused, zero-dependency gate.
- Does not resolve `aws_security_group_rule` / module indirection across resources; each change is
  judged on its own `after` block.
