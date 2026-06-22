"""Scanner framework — base class and plugin registry for vulnerability scanners."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from vulnhawk.core.crawler import CrawlResult


@dataclass
class Vulnerability:
    """A discovered vulnerability."""
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    url: str
    description: str
    evidence: str | None = None
    remediation: str = ""
    scanner_name: str = ""
    cvss_score: float | None = None
    references: list[str] = field(default_factory=list)


class BaseScanner(ABC):
    """
    Base class for all vulnerability scanners.

    To create a new scanner:
    1. Create a new file in vulnhawk/scanners/
    2. Define a class that inherits from BaseScanner
    3. Implement the scan() method
    4. The scanner will be automatically discovered and registered
    """

    name: str = "Unknown Scanner"
    description: str = ""

    @abstractmethod
    async def scan(self, target: CrawlResult) -> list[Vulnerability]:
        """
        Run the scan against the crawl results.

        Args:
            target: CrawlResult containing discovered URLs, forms, params, headers

        Returns:
            List of discovered Vulnerability objects
        """
        ...


# ──────────────────────────────────────────────
# Scanner Registry (Auto-Discovery)
# ──────────────────────────────────────────────

_registered_scanners: list[type[BaseScanner]] = []


def register_scanner(scanner_class: type[BaseScanner]):
    """Register a scanner class. Used as a decorator."""
    _registered_scanners.append(scanner_class)
    return scanner_class


def discover_scanners():
    """Auto-discover and import all scanner modules from the scanners/ directory."""
    scanners_dir = Path(__file__).parent.parent / "scanners"

    if not scanners_dir.exists():
        return

    for scanner_file in scanners_dir.glob("*.py"):
        if scanner_file.name.startswith("_"):
            continue
        module_name = f"vulnhawk.scanners.{scanner_file.stem}"
        try:
            import_module(module_name)
        except ImportError as e:
            print(f"Warning: Could not load scanner {module_name}: {e}")


def get_all_scanners() -> list[BaseScanner]:
    """Get instances of all registered scanners."""
    discover_scanners()
    return [scanner_cls() for scanner_cls in _registered_scanners]


# ──────────────────────────────────────────────
# Scanner Runner
# ──────────────────────────────────────────────

async def run_all_scanners(
    crawl_result: CrawlResult,
    console: Console | None = None,
) -> list[Vulnerability]:
    """
    Run all registered scanners against the crawl results.

    Args:
        crawl_result: Results from the crawler
        console: Rich console for progress output

    Returns:
        All discovered vulnerabilities, sorted by severity
    """
    scanners = get_all_scanners()

    if not scanners:
        if console:
            console.print("  ⚠️  No scanners found!")
        return []

    all_vulnerabilities: list[Vulnerability] = []

    if console:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            for scanner in scanners:
                task = progress.add_task(f"Running {scanner.name}...", total=None)
                try:
                    vulns = await scanner.scan(crawl_result)
                    for v in vulns:
                        v.scanner_name = scanner.name
                    all_vulnerabilities.extend(vulns)
                    progress.update(
                        task,
                        description=f"✅ {scanner.name} — {len(vulns)} finding(s)",
                        completed=True,
                        total=1,
                    )
                except Exception as e:
                    progress.update(
                        task,
                        description=f"❌ {scanner.name} — Error: {e}",
                        completed=True,
                        total=1,
                    )
    else:
        # Run without progress display
        for scanner in scanners:
            try:
                vulns = await scanner.scan(crawl_result)
                for v in vulns:
                    v.scanner_name = scanner.name
                all_vulnerabilities.extend(vulns)
            except Exception:
                pass

    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 5))

    return all_vulnerabilities
