"""URL and string helper utilities for VulnHawk."""

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """Normalize a URL by stripping fragments and trailing slashes."""
    url = url.split("#")[0]  # Remove fragment
    url = url.rstrip("/") if url.count("/") > 2 else url  # Don't strip root /
    return url


def inject_param(url: str, param: str, value: str) -> str:
    """Inject a value into a specific URL query parameter."""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    query_params[param] = [value]
    new_query = urlencode(query_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def get_params(url: str) -> dict[str, list[str]]:
    """Extract all query parameters from a URL."""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def same_domain(url1: str, url2: str) -> bool:
    """Check if two URLs belong to the same domain."""
    return urlparse(url1).netloc == urlparse(url2).netloc


def is_safe_url(url: str) -> bool:
    """Check if a URL is safe to scan (http/https scheme)."""
    scheme = urlparse(url).scheme
    return scheme in ("http", "https")


def truncate(text: str, max_len: int = 200) -> str:
    """Truncate text to a maximum length with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def extract_domain(url: str) -> str:
    """Extract the domain (netloc) from a URL."""
    return urlparse(url).netloc
