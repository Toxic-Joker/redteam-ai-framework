"""Lightweight HTML crawler: discovers real pages and forms instead of

guessing path segments from a static wordlist (gobuster/ffuf). Needed to
reach pages with parameters (e.g. DVWA /vulnerabilities/sqli/?id=1) that no
generic wordlist contains - a wordlist only knows file/folder names, never
the parameters a page actually expects.

Doesn't inherit from BaseTool: this isn't an external subprocess but a pure
async HTTP client, BaseTool's machinery (build_command/_run around a CLI
binary) doesn't apply here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass
class CrawlResult:
    # URLs that already carry parameters (<a href> links or GET forms
    # whose fields were synthesized into a query string).
    urls_with_params: list[str] = field(default_factory=list)
    # POST forms: sqlmap tests them via --data, never via a plain URL.
    post_forms: list[dict] = field(default_factory=list)
    visited: list[str] = field(default_factory=list)


class CrawlerTool:
    name = "crawler"

    async def crawl(
        self,
        base_url: str,
        cookie: Optional[str] = None,
        max_pages: int = 30,
        timeout: int = 10,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> CrawlResult:
        # transport: injection point for tests (httpx.MockTransport), never
        # used in production (None => httpx's real network transport).
        result = CrawlResult()
        seen: set[str] = set()
        queue: list[str] = [base_url]
        headers = {"Cookie": cookie} if cookie else {}
        base_host = urlparse(base_url).netloc

        async with httpx.AsyncClient(
            headers=headers, timeout=timeout, follow_redirects=True, transport=transport
        ) as client:
            while queue and len(seen) < max_pages:
                url = queue.pop(0)
                if url in seen:
                    continue
                seen.add(url)

                try:
                    response = await client.get(url)
                except Exception:  # noqa: BLE001 - an unreachable page must not stop the crawl
                    continue

                result.visited.append(url)
                if "text/html" not in response.headers.get("content-type", ""):
                    continue

                soup = BeautifulSoup(response.text, "html.parser")
                self._extract_links(soup, url, base_host, seen, queue, result, max_pages)
                self._extract_forms(soup, url, base_host, result)

        result.urls_with_params = sorted(set(result.urls_with_params))
        return result

    @staticmethod
    def _extract_links(
        soup: BeautifulSoup,
        page_url: str,
        base_host: str,
        seen: set[str],
        queue: list[str],
        result: CrawlResult,
        max_pages: int,
    ) -> None:
        for anchor in soup.find_all("a", href=True):
            link = urljoin(page_url, anchor["href"]).split("#", 1)[0]
            if urlparse(link).netloc != base_host:
                continue
            if parse_qs(urlparse(link).query):
                result.urls_with_params.append(link)
            if link not in seen and len(seen) + len(queue) < max_pages:
                queue.append(link)

    @staticmethod
    def _extract_forms(soup: BeautifulSoup, page_url: str, base_host: str, result: CrawlResult) -> None:
        for form in soup.find_all("form"):
            action = urljoin(page_url, form.get("action") or page_url)
            if urlparse(action).netloc != base_host:
                continue
            method = (form.get("method") or "GET").strip().upper()
            fields = [
                field_el.get("name")
                for field_el in form.find_all(["input", "textarea", "select"])
                if field_el.get("name")
            ]
            if not fields:
                continue
            # Generic test value per field: enough to give sqlmap a real
            # parameter to test, not to fill in the form in a semantically
            # correct way.
            payload = "&".join(f"{name}=1" for name in fields)
            if method == "GET":
                result.urls_with_params.append(f"{action}?{payload}")
            else:
                result.post_forms.append({"url": action, "data": payload})
