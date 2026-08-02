# CloudSec Scanner

A multi-cloud security posture scanner. Point it at an AWS account (Azure/GCP
scaffolded on the same interface) and it comes back with a scored report of
misconfigurations, IAM problems, network exposure, and secrets hygiene
issues — each with a plain-English description and a concrete fix.

## Easy install (recommended)

**Windows:** double-click `setup.bat`
**Mac/Linux:** open a terminal in this folder and run `./setup.sh`

That's it. It checks Python is installed, creates an isolated environment,
installs everything, and runs a self-check so you know immediately if
something's wrong instead of hitting a confusing error later.

Afterward, always run the tool through the wrapper — it handles the
environment for you, no manual activation needed:

```
Windows:    run.bat scan --provider aws
Mac/Linux:  ./run.sh scan --provider aws
```

If something seems broken at any point, run `run.bat doctor` (or
`./run.sh doctor`) — it checks your Python version, dependencies, and
whether checks loaded correctly, and tells you exactly what's wrong.

<details>
<summary>Manual install (if you'd rather do it yourself)</summary>

```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -e .
cloudsec-scanner doctor
```
</details>

---


```
$ cloudsec-scanner scan --provider aws --profile prod
CloudSec Scanner — starting aws scan
Registered checks: 20
  running AWS_DATA_001 ...
  running AWS_DATA_002 ...
  ...
JSON report written: cloudsec-report.json
HTML report written: cloudsec-report.html

Posture score: 42/100
Total findings: 31  (critical=4, high=9, medium=12, low=6)
Scan duration: 18.3s
```

## Quickstart

```bash
pip install -e .
# Uses your existing AWS credentials (env vars, ~/.aws/credentials, or --profile)
cloudsec-scanner scan --provider aws --profile default --format json,html
cloudsec-scanner list-checks --provider aws
```

Required IAM permissions are read-only: `s3:Get*`, `iam:List*`/`iam:Get*`,
`ec2:Describe*`, `rds:Describe*`, `lambda:List*`/`GetFunction`,
`secretsmanager:List*`. Consider the `SecurityAudit` managed policy as a
starting point.

For Azure or GCP:
```bash
pip install -e ".[azure]"
cloudsec-scanner scan --provider azure --subscription-id <id>

pip install -e ".[gcp]"
cloudsec-scanner scan --provider gcp --project-id <id>
```

## Architecture

```
cloudsec_scanner/
  core/
    finding.py        Finding + Severity + Category — the one shape every
                       check across every provider produces
    scanner_base.py    BaseCheck, CheckRegistry, BaseProviderScanner —
                       the plugin architecture
    report.py          posture scoring + JSON/HTML report generation
  providers/
    aws/
      scanner.py        boto3 session setup, orchestration
      checks/
        s3_checks.py     4 checks — public access, encryption, versioning
        iam_checks.py    5 checks — MFA, stale keys, wildcard policies, root keys, password policy
        network_checks.py  4 checks — open security groups, default VPC, flow logs
        secrets_checks.py  3 checks — Lambda plaintext secrets, rotation, public snapshots
        data_checks.py     4 checks — RDS/EBS public access & encryption
    azure/scanner.py     2 checks (NSG open ports, public storage) — same pattern
    gcp/scanner.py       2 checks (public GCS buckets, open firewall rules) — same pattern
  cli.py                click-based CLI: `scan` and `list-checks` commands
```

**Adding a check** is one class:

```python
@register_aws_check
class MyNewCheck(BaseCheck):
    check_id = "AWS_XYZ_001"
    title = "Short description of what's wrong"
    provider = "aws"

    def run(self) -> list[Finding]:
        client = self.session.client("some-service")
        # ... call the API, evaluate the condition ...
        return [Finding(...)]
```

Nothing else needs to change — the CLI, the registry, and the report
generator all pick it up automatically. Azure and GCP checks follow the
identical pattern against `@register_azure_check` / `@register_gcp_check`.

## Scoring

Posture score uses asymptotic decay (`100 / (1 + penalty/100)`) rather than
linear subtraction from severity-weighted findings (critical=40, high=20,
medium=8, low=3). This keeps the score differentiating "bad" from
"catastrophic" instead of flooring at 0 the moment an account has more than
a couple of critical issues — which linear subtraction does almost
immediately.

## Dashboard

`cloudsec-dashboard.jsx` is a standalone React dashboard that reads any
`report.json` the CLI produces (there's a "Load report.json" button) and
visualizes posture score, severity/category breakdowns, and a filterable,
searchable findings table with remediation guidance per finding. It ships
with demo data pre-loaded so you can see it immediately.

## What's implemented vs. scaffolded

- **AWS: 20 checks, fully implemented** across S3, IAM, EC2/VPC networking,
  Lambda/Secrets Manager/snapshot exposure, and RDS/EBS. This is the real
  depth of the product today.
- **Azure/GCP: 2 checks each, fully implemented**, proving the plugin
  architecture works identically across providers. Treat these as a
  template — the fastest way to grow coverage is copying one of these
  classes and pointing it at a different `azure-mgmt-*` / `google-cloud-*`
  client.

## Roadmap ideas for v2

- Continuous scanning (scheduled runs, diff against last scan, Slack/email
  alerts on new criticals)
- CIS Benchmark / SOC 2 / PCI-DSS control mapping per finding
- Auto-remediation (opt-in Terraform/CLI snippets per finding)
- Multi-account/org-wide scanning (AWS Organizations, Azure management
  groups, GCP folders)
- Historical trend tracking of posture score over time
