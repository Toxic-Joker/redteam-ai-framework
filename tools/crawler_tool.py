"""Crawler HTML leger : decouvre pages et formulaires reels au lieu de deviner

des segments de chemin depuis une wordlist statique (gobuster/ffuf). Necessaire
pour atteindre les pages avec parametres (ex. DVWA /vulnerabilities/sqli/?id=1)
qu'aucune wordlist generique ne contient - une wordlist ne connait que des noms
de fichiers/dossiers, jamais les parametres qu'une page attend reellement.

N'herite pas de BaseTool : ce n'est pas un sous-processus externe mais un
client HTTP asynchrone pur, la mecanique de BaseTool (build_command/_run
autour d'un binaire CLI) ne s'applique pas ici.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup


@dataclass
class CrawlResult:
    # URLs avec parametres deja presents (liens <a href> ou formulaires GET
    # dont les champs ont ete synthetises en chaine de requete).
    urls_with_params: list[str] = field(default_factory=list)
    # Formulaires POST : sqlmap les teste via --data, jamais via une simple URL.
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
        # transport : point d'injection pour les tests (httpx.MockTransport),
        # jamais utilise en production (None => transport reseau reel d'httpx).
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
                except Exception:  # noqa: BLE001 - une page injoignable ne doit pas arreter le crawl
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
            # Valeur de test generique par champ : suffisant pour donner a
            # sqlmap un parametre reel a tester, pas pour remplir le
            # formulaire de facon semantiquement correcte.
            payload = "&".join(f"{name}=1" for name in fields)
            if method == "GET":
                result.urls_with_params.append(f"{action}?{payload}")
            else:
                result.post_forms.append({"url": action, "data": payload})
