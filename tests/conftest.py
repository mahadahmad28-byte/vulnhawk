"""Test fixtures and shared configuration for VulnHawk tests."""

import pytest

from vulnhawk.core.crawler import CrawlResult, FormData


@pytest.fixture
def sample_crawl_result():
    """Create a sample CrawlResult for testing scanners."""
    return CrawlResult(
        base_url="http://testsite.local",
        urls=[
            "http://testsite.local",
            "http://testsite.local/login",
            "http://testsite.local/search?q=test",
            "http://testsite.local/profile?id=1",
        ],
        forms=[
            FormData(
                url="http://testsite.local/login",
                action="http://testsite.local/login",
                method="POST",
                inputs=[
                    {"name": "username", "type": "text", "value": ""},
                    {"name": "password", "type": "password", "value": ""},
                ],
            ),
            FormData(
                url="http://testsite.local/search",
                action="http://testsite.local/search",
                method="GET",
                inputs=[
                    {"name": "q", "type": "text", "value": ""},
                ],
            ),
        ],
        parameters={
            "http://testsite.local/search?q=test": ["q"],
            "http://testsite.local/profile?id=1": ["id"],
        },
        headers={
            "http://testsite.local": {
                "server": "Apache/2.4.41",
                "x-powered-by": "PHP/7.4.3",
                "content-type": "text/html; charset=UTF-8",
            },
        },
        cookies={},
        technologies=["Server: Apache/2.4.41", "Powered-By: PHP/7.4.3"],
    )


@pytest.fixture
def secure_crawl_result():
    """Create a CrawlResult representing a well-secured site."""
    return CrawlResult(
        base_url="https://secure.local",
        urls=["https://secure.local"],
        forms=[],
        parameters={},
        headers={
            "https://secure.local": {
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "x-content-type-options": "nosniff",
                "x-xss-protection": "1; mode=block",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "camera=(), microphone=()",
                "content-type": "text/html; charset=UTF-8",
            },
        },
        cookies={},
        technologies=[],
    )
