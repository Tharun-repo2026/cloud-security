"""
Command-line interface.

Usage:
    cloudsec-scanner scan --provider aws --profile my-profile --format json,html
    cloudsec-scanner scan --provider azure --subscription-id <id>
    cloudsec-scanner scan --provider gcp --project-id <id>
    cloudsec-scanner list-checks --provider aws
"""
from __future__ import annotations

import sys
import time

import click

from cloudsec_scanner.core.report import build_report, save_html_report, save_json_report


@click.group()
def main():
    """CloudSec Scanner — multi-cloud security posture scanning."""


@main.command()
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"]), required=True)
@click.option("--profile", default=None, help="AWS named profile (aws only)")
@click.option("--region", default="us-east-1", help="AWS default region (aws only)")
@click.option("--subscription-id", default=None, help="Azure subscription id (azure only)")
@click.option("--project-id", default=None, help="GCP project id (gcp only)")
@click.option("--output", default="cloudsec-report", help="Output file basename (no extension)")
@click.option("--format", "fmt", default="json", help="Comma-separated: json,html")
def scan(provider, profile, region, subscription_id, project_id, output, fmt):
    """Run all registered checks for a provider and write a report."""
    click.secho(f"CloudSec Scanner — starting {provider} scan", fg="cyan", bold=True)
    started = time.time()

    if provider == "aws":
        from cloudsec_scanner.providers.aws.scanner import AWSScanner
        scanner = AWSScanner(profile=profile, region=region)
        account_id = scanner.account_id
    elif provider == "azure":
        if not subscription_id:
            click.secho("--subscription-id is required for azure", fg="red")
            sys.exit(1)
        from cloudsec_scanner.providers.azure.scanner import AzureScanner
        scanner = AzureScanner(subscription_id=subscription_id)
        account_id = subscription_id
    else:
        if not project_id:
            click.secho("--project-id is required for gcp", fg="red")
            sys.exit(1)
        from cloudsec_scanner.providers.gcp.scanner import GCPScanner
        scanner = GCPScanner(project_id=project_id)
        account_id = project_id

    total_checks = len(scanner.registry)
    click.echo(f"Registered checks: {total_checks}")

    def progress(check_id: str):
        click.echo(f"  running {check_id} ...")

    findings = scanner.scan(progress_cb=progress)
    duration = time.time() - started

    report = build_report(findings, provider=provider, account_id=account_id,
                           scan_duration_seconds=round(duration, 2))

    formats = [f.strip() for f in fmt.split(",")]
    if "json" in formats:
        path = save_json_report(report, f"{output}.json")
        click.secho(f"JSON report written: {path}", fg="green")
    if "html" in formats:
        path = save_html_report(report, f"{output}.html")
        click.secho(f"HTML report written: {path}", fg="green")

    score = report["posture_score"]
    color = "green" if score >= 80 else "yellow" if score >= 50 else "red"
    click.echo()
    click.secho(f"Posture score: {score}/100", fg=color, bold=True)
    click.echo(f"Total findings: {len(findings)}  "
               f"(critical={report['summary']['by_severity']['CRITICAL']}, "
               f"high={report['summary']['by_severity']['HIGH']}, "
               f"medium={report['summary']['by_severity']['MEDIUM']}, "
               f"low={report['summary']['by_severity']['LOW']})")
    click.echo(f"Scan duration: {duration:.1f}s")


@main.command("list-checks")
@click.option("--provider", type=click.Choice(["aws", "azure", "gcp"]), required=True)
def list_checks(provider):
    """List every registered check for a provider."""
    if provider == "aws":
        from cloudsec_scanner.providers.aws.scanner import AWSScanner
        registry = AWSScanner.registry
    elif provider == "azure":
        from cloudsec_scanner.core.scanner_base import AZURE_REGISTRY
        registry = AZURE_REGISTRY
    else:
        from cloudsec_scanner.core.scanner_base import GCP_REGISTRY
        registry = GCP_REGISTRY

    for check_cls in registry.all():
        click.echo(f"{check_cls.check_id:<20} {check_cls.title}")
    click.echo(f"\n{len(registry)} checks registered for {provider}")


@main.command()
def doctor():
    """Check that the environment is set up correctly."""
    import platform

    click.secho("CloudSec Scanner — environment check", fg="cyan", bold=True)
    click.echo()

    ok = True

    # Python version
    py_version = sys.version_info
    click.echo(f"Python version: {platform.python_version()}")
    if py_version < (3, 9):
        click.secho("  [X] Python 3.9+ required", fg="red")
        ok = False
    elif py_version >= (3, 13):
        click.secho("  [!] Very new Python version — if boto3 install failed, "
                     "try Python 3.11 or 3.12 instead", fg="yellow")
    else:
        click.secho("  [OK]", fg="green")

    # boto3
    try:
        import boto3
        click.echo(f"boto3: {boto3.__version__}")
        click.secho("  [OK]", fg="green")
    except ImportError:
        click.secho("boto3: NOT INSTALLED", fg="red")
        click.echo("  Run: pip install -e .")
        ok = False

    # click itself (trivially true if we're here, but confirms the install path)
    try:
        from importlib.metadata import version as pkg_version
        click.echo(f"click: {pkg_version('click')}")
    except Exception:
        click.echo("click: installed")
    click.secho("  [OK]", fg="green")

    # registered checks
    try:
        from cloudsec_scanner.providers.aws.scanner import AWSScanner
        n = len(AWSScanner.registry)
        click.echo(f"AWS checks registered: {n}")
        click.secho("  [OK]" if n > 0 else "  [X] No checks registered — install may be broken",
                     fg="green" if n > 0 else "red")
        ok = ok and n > 0
    except Exception as e:
        click.secho(f"AWS checks: failed to load ({e})", fg="red")
        ok = False

    # AWS credentials (optional — just informational)
    click.echo()
    try:
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        click.secho(f"AWS credentials found: account {identity['Account']}", fg="green")
    except Exception:
        click.secho("AWS credentials: not configured (fine if you're just testing — "
                     "run 'aws configure' before a real scan)", fg="yellow")

    click.echo()
    if ok:
        click.secho("Everything looks good.", fg="green", bold=True)
    else:
        click.secho("Some checks failed — see [X] items above.", fg="red", bold=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
