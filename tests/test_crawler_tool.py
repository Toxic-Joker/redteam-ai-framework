"""Le crawler doit trouver ce qu'une wordlist ne peut pas : des pages avec

parametres reels, y compris synthetisees a partir des champs d'un
formulaire (GET) ou preparees pour sqlmap --data (POST).
"""
import httpx
import pytest

from tools.crawler_tool import CrawlerTool

PAGE_HOME = """
<html><body>
<a href="/page2">Page 2</a>
<a href="http://evil.example/x?y=1">lien externe, doit etre ignore</a>
<form method="GET" action="/vulnerabilities/sqli/">
  <input name="id">
  <input type="submit" name="Submit" value="Submit">
</form>
<form method="POST" action="/login.php">
  <input name="username">
  <input name="password">
</form>
</body></html>
"""

PAGE_2 = "<html><body>rien ici</body></html>"


def _make_handler():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=PAGE_HOME)
        if request.url.path == "/page2":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=PAGE_2)
        return httpx.Response(404, headers={"content-type": "text/html"}, text="not found")

    return handler


@pytest.mark.asyncio
async def test_crawler_synthesizes_url_from_get_form_fields():
    tool = CrawlerTool()
    transport = httpx.MockTransport(_make_handler())
    result = await tool.crawl("http://target/", transport=transport)

    matching = [u for u in result.urls_with_params if "/vulnerabilities/sqli/" in u]
    assert matching, result.urls_with_params
    assert "id=1" in matching[0]


@pytest.mark.asyncio
async def test_crawler_collects_post_forms_separately():
    tool = CrawlerTool()
    transport = httpx.MockTransport(_make_handler())
    result = await tool.crawl("http://target/", transport=transport)

    assert len(result.post_forms) == 1
    assert result.post_forms[0]["url"] == "http://target/login.php"
    assert "username=1" in result.post_forms[0]["data"]
    assert "password=1" in result.post_forms[0]["data"]


@pytest.mark.asyncio
async def test_crawler_follows_same_host_links_only():
    tool = CrawlerTool()
    transport = httpx.MockTransport(_make_handler())
    result = await tool.crawl("http://target/", transport=transport)

    assert "http://target/page2" in result.visited
    assert not any("evil.example" in u for u in result.visited)
    assert not any("evil.example" in u for u in result.urls_with_params)


@pytest.mark.asyncio
async def test_crawler_sends_cookie_header_when_provided():
    seen_cookie = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookie["value"] = request.headers.get("cookie")
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html></html>")

    tool = CrawlerTool()
    transport = httpx.MockTransport(handler)
    await tool.crawl("http://target/", cookie="PHPSESSID=abc", transport=transport)

    assert seen_cookie["value"] == "PHPSESSID=abc"


@pytest.mark.asyncio
async def test_crawler_respects_max_pages():
    def handler(request: httpx.Request) -> httpx.Response:
        # Chaque page pointe vers une page suivante, a l'infini si on ne
        # bornait pas le nombre de pages visitees.
        n = int(request.url.path.strip("/") or 0)
        return httpx.Response(
            200, headers={"content-type": "text/html"}, text=f'<a href="/{n + 1}">next</a>'
        )

    tool = CrawlerTool()
    transport = httpx.MockTransport(handler)
    result = await tool.crawl("http://target/", max_pages=3, transport=transport)

    assert len(result.visited) <= 3
