"""HTTP client utilities — shared async HTTP client with common configurations."""

import httpx


def create_client(
    timeout: float = 10.0,
    follow_redirects: bool = True,
    verify_ssl: bool = False,
) -> httpx.AsyncClient:
    """Create a configured async HTTP client for scanning."""
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        verify=verify_ssl,
        headers={
            "User-Agent": "VulnHawk/1.0 Security Scanner",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        },
    )
