"""
dfir-memdump CLI entry point.

Usage:
    dfir-memdump analyze <image> [options]
    dfir-memdump analyze <image> --format json --output ./reports
    dfir-memdump analyze <image> --profile Win10x64_19041 --no-vt
"""

from __future__ import annotations
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# Severity colours for rich output
SEV_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim",
}


@click.group()
@click.option("--debug", is_flag=True, help="Enable debug logging")
def cli(debug: bool):
    """dfir-memdump — Memory forensics triage tool powered by Volatility3."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


@cli.command()
@click.argument("image", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option("--profile",  "-p", default=None, help="Volatility3 profile override (e.g. Win10x64_19041)")
@click.option("--output",   "-o", default="./reports", show_default=True, type=click.Path(path_type=Path), help="Output directory")
@click.option("--format",   "-f", "fmt", default="all", show_default=True, type=click.Choice(["json", "markdown", "html", "all"]), help="Report format (all = JSON + Markdown + HTML)")
@click.option("--no-vt",    is_flag=True, help="Skip VirusTotal hash lookups")
@click.option("--no-yara",  is_flag=True, help="Skip YARA scanning")
@click.option("--stem",     default=None, help="Report filename stem (default: <image>.triage)")
def analyze(
    image: Path,
    profile: str | None,
    output: Path,
    fmt: str,
    no_vt: bool,
    no_yara: bool,
    stem: str | None,
):
    """Analyze a memory image and generate an IR triage report."""
    from dfir_memdump.runner import MemoryAnalyzer
    from dfir_memdump.report.builder import build_report
    from dfir_memdump.exceptions import ImageNotFoundError, Vol3NotFoundError

    console.print(f"\n[bold cyan]dfir-memdump[/bold cyan] — analyzing [bold]{image.name}[/bold]\n")

    try:
        analyzer = MemoryAnalyzer(
            image_path = image,
            profile    = profile,
            skip_vt    = no_vt,
            skip_yara  = no_yara,
        )
        with console.status("[bold green]Running Volatility3 plugins…", spinner="dots"):
            report = analyzer.run()
    except ImageNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Vol3NotFoundError as e:
        console.print(f"[red]Error:[/red] Volatility3 not found. {e}")
        console.print("  Install: pip install volatility3  or set VOL3_PATH in .env")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        logging.exception("Unhandled exception during analysis")
        sys.exit(1)

    # ── Print executive summary ──────────────────────────────────────────────
    console.print("[bold]Executive Summary[/bold]")
    console.print("─" * 60)
    for line in (report.executive_summary or "").splitlines():
        console.print(line)
    console.print()

    # ── Print findings table ─────────────────────────────────────────────────
    findings = report.findings_by_severity()
    if findings:
        table = Table(
            title=f"Findings ({len(findings)} total)",
            box=box.ROUNDED,
            show_lines=False,
        )
        table.add_column("Sev",      style="bold", width=10)
        table.add_column("Category", width=12)
        table.add_column("PID",      width=8)
        table.add_column("Process",  width=18)
        table.add_column("Title",    no_wrap=False)

        for f in findings:
            sev_style = SEV_STYLE.get(f.severity.value, "")
            table.add_row(
                Text(f.severity.value, style=sev_style),
                f.category.value,
                str(f.affected_pid or ""),
                f.affected_process or "",
                f.title[:80],
            )
        console.print(table)
    else:
        console.print("[green]No findings.[/green]")

    # ── Print MITRE techniques ───────────────────────────────────────────────
    techniques = report.unique_mitre_techniques()
    if techniques:
        console.print(f"\n[bold]MITRE ATT&CK:[/bold] {', '.join(techniques)}")

    # ── Write reports ────────────────────────────────────────────────────────
    report_stem = stem or f"{image.stem}.triage"
    generated = build_report(report, output_dir=output, stem=report_stem, fmt=fmt)

    console.print(f"\n[bold green]Reports written:[/bold green]")
    for p in generated:
        icon = "🌐" if p.suffix == ".html" else ("📄" if p.suffix == ".md" else "📋")
        console.print(f"  {icon}  {p}")
    html_paths = [p for p in generated if p.suffix == ".html"]
    if html_paths:
        console.print(f"\n[bold cyan]Open the HTML report in your browser to view the full interactive report.[/bold cyan]")
        console.print(f"  [dim]file://{html_paths[0].resolve()}[/dim]")
    console.print()


@cli.command()
def version():
    """Print version and exit."""
    from dfir_memdump import __version__
    console.print(f"dfir-memdump {__version__}")


def main():
    cli()


if __name__ == "__main__":
    main()
