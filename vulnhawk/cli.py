"""VulnHawk CLI — Beautiful command-line interface for the vulnerability scanner."""

import asyncio
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table
from rich.text import Text

from vulnhawk.core.crawler import crawl_target
from vulnhawk.core.reporter import generate_html_report, generate_json_report, generate_pdf_report
from vulnhawk.core.scanner import run_all_scanners

app = typer.Typer(
    name="vulnhawk",
    help="🦅 VulnHawk — Async Web Vulnerability Scanner",
    add_completion=False,
)
console = Console()


BANNER = """
[bold red]
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝ 
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗ 
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
[/bold red]
[dim]Async Web Vulnerability Scanner v1.0.0[/dim]
"""


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL to scan (e.g., http://localhost:3000)"),
    depth: int = typer.Option(2, "--depth", "-d", help="Maximum crawl depth"),
    threads: int = typer.Option(10, "--threads", "-t", help="Maximum concurrent requests"),
    output: str = typer.Option(None, "--output", "-o", help="Output report file path"),
    report_format: str = typer.Option("html", "--format", "-f", help="Report format: html, json, pdf"),
    login_url: str = typer.Option(None, "--login-url", help="URL of the login form for authenticated scanning"),
    username: str = typer.Option(None, "--username", "-u", help="Username for authenticated scanning"),
    password: str = typer.Option(None, "--password", "-p", help="Password for authenticated scanning", hide_input=True),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress the banner"),
):
    """
    🔍 Scan a target URL for web vulnerabilities.

    Example: vulnhawk scan http://localhost:3000 --depth 3

    Authenticated scan: vulnhawk scan http://localhost:3000 --login-url http://localhost:3000/login --username admin --password secret
    """
    if not no_banner:
        console.print(BANNER)

    # Validate URL
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    config_text = (
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Depth:[/bold] {depth}\n"
        f"[bold]Threads:[/bold] {threads}\n"
        f"[bold]Format:[/bold] {report_format}"
    )
    if login_url:
        config_text += f"\n[bold]Auth:[/bold] {login_url} (user: {username})"

    console.print(Panel(
        config_text,
        title="[bold cyan]Scan Configuration[/bold cyan]",
        border_style="cyan",
    ))
    console.print()

    # Run the async scan
    asyncio.run(_run_scan(target, depth, threads, output, report_format, login_url, username, password))


async def _run_scan(
    target: str,
    depth: int,
    threads: int,
    output: str | None,
    report_format: str,
    login_url: str | None,
    username: str | None,
    password: str | None,
):
    """Execute the full scan pipeline."""

    # Phase 1: Crawling
    auth_note = " (authenticated)" if login_url else ""
    console.print(f"[bold cyan][1/3] Crawling target{auth_note}...[/bold cyan]")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Discovering URLs and forms...", total=None)
        crawl_result = await crawl_target(
            target,
            max_depth=depth,
            max_concurrent=threads,
            login_url=login_url,
            username=username,
            password=password,
        )
        progress.update(task, completed=True, total=1)

    console.print(
        f"  ✅ Found [bold green]{len(crawl_result.urls)}[/bold green] URLs "
        f"and [bold green]{len(crawl_result.forms)}[/bold green] forms\n"
    )

    # Phase 2: Scanning
    console.print("[bold cyan][2/3] Running vulnerability scanners...[/bold cyan]")
    vulnerabilities = await run_all_scanners(crawl_result, console=console)

    # Phase 3: Results
    console.print("\n[bold cyan][3/3] Generating report...[/bold cyan]\n")
    _display_results(vulnerabilities, target)

    # Generate report file
    report_dir = Path("reports")
    report_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]

    if not output:
        ext = report_format if report_format in ("html", "json", "pdf") else "html"
        output = str(report_dir / f"vulnhawk_{domain}_{timestamp}.{ext}")

    if report_format == "json":
        report_path = generate_json_report(vulnerabilities, target, output)
    elif report_format == "pdf":
        try:
            report_path = generate_pdf_report(vulnerabilities, target, output)
        except ImportError as e:
            console.print(f"[yellow]⚠️  {e}[/yellow]")
            console.print("[dim]Falling back to HTML report...[/dim]")
            output = output.replace(".pdf", ".html")
            report_path = generate_html_report(vulnerabilities, target, output)
    else:
        report_path = generate_html_report(vulnerabilities, target, output)

    console.print(f"\n📄 Report saved: [bold green]{report_path}[/bold green]")


def _display_results(vulnerabilities: list, target: str):
    """Display scan results in a beautiful table."""

    if not vulnerabilities:
        console.print(Panel(
            "[bold green]✅ No vulnerabilities found![/bold green]\n"
            "The target appears to be secure against the tested attack vectors.",
            title="[bold green]Scan Complete[/bold green]",
            border_style="green",
        ))
        return

    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for vuln in vulnerabilities:
        severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1

    # Severity colors
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }

    # Summary table
    summary_table = Table(title="Scan Results Summary", border_style="cyan")
    summary_table.add_column("Severity", style="bold", width=12)
    summary_table.add_column("Count", justify="center", width=8)
    summary_table.add_column("Details", width=55)

    for severity, count in severity_counts.items():
        if count > 0:
            color = severity_colors[severity]
            detail_vulns = [v for v in vulnerabilities if v.severity == severity]
            details = "; ".join(v.title for v in detail_vulns[:3])
            if len(detail_vulns) > 3:
                details += f" (+{len(detail_vulns) - 3} more)"
            summary_table.add_row(
                Text(severity, style=color),
                Text(str(count), style=color),
                details,
            )

    console.print(summary_table)

    # Detailed findings
    console.print("\n[bold]Detailed Findings:[/bold]\n")
    for i, vuln in enumerate(vulnerabilities, 1):
        color = severity_colors.get(vuln.severity, "white")
        cvss_info = f"\n[bold]CVSS Score:[/bold] {vuln.cvss_score}" if vuln.cvss_score is not None else ""
        console.print(Panel(
            f"[bold]URL:[/bold] {vuln.url}\n"
            f"[bold]Severity:[/bold] [{color}]{vuln.severity}[/{color}]{cvss_info}\n"
            f"[bold]Description:[/bold] {vuln.description}\n"
            f"[bold]Evidence:[/bold] {vuln.evidence or 'N/A'}\n"
            f"[bold]Remediation:[/bold] {vuln.remediation}",
            title=f"[{color}]#{i} — {vuln.title}[/{color}]",
            border_style=color.replace("bold ", ""),
        ))


@app.command()
def version():
    """Show VulnHawk version."""
    console.print("[bold]VulnHawk[/bold] v1.0.0")


if __name__ == "__main__":
    app()
