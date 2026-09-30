import os
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

test_root = Path(tempfile.mkdtemp(prefix="appora-legal-links-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(test_root / 'test.db').as_posix()}"
os.environ["PRIVATE_UPLOAD_ROOT"] = str(test_root / "uploads")
os.environ["SECRET_KEY"] = "legal-link-test"
os.environ["ADMIN_USERNAME"] = "legal_admin"
os.environ["ADMIN_EMAIL"] = "legal-admin@example.com"
os.environ["ADMIN_PASSWORD"] = "LegalAdmin123!"
os.environ["AUTO_MIGRATE"] = "true"

from app import app  # noqa: E402


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)


pages = {
    "/policies",
    "/privacy",
    "/terms",
    "/developer-agreement",
    "/acceptable-use",
    "/copyright",
    "/data-retention",
    "/grievance",
    "/security-and-legal",
}
client = app.test_client()

for page in pages:
    response = client.get(page)
    assert response.status_code == 200, (page, response.status_code)
    parser = LinkParser()
    parser.feed(response.get_data(as_text=True))
    for href in parser.links:
        assert href != "#" and "example.invalid" not in href, (page, href)
        parsed = urlsplit(href)
        if parsed.scheme == "mailto":
            assert "@" in parsed.path, (page, href)
        elif not parsed.scheme and parsed.path.startswith("/"):
            linked = client.get(parsed.path)
            assert linked.status_code < 400, (page, href, linked.status_code)

print(f"Legal link checks passed for {len(pages)} pages.")
