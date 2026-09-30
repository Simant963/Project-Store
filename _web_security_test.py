"""Small regression check for browser and query-input security controls."""

import os

os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AUTO_MIGRATE"] = "false"
os.environ["FLASK_DEBUG"] = "true"

from app import app
from application.controllers import escaped_search_term, is_valid_web_url
from application.database import db


@app.get("/_security-test/exception")
def confidential_exception_test():
    raise RuntimeError("DO_NOT_EXPOSE_DATABASE_PASSWORD_OR_INTERNAL_PATH")


def main():
    assert app.debug is False
    assert app.config["PROPAGATE_EXCEPTIONS"] is False
    assert escaped_search_term(r"50%_off\sale") == r"50\%\_off\\sale"
    assert is_valid_web_url("https://example.com/privacy")
    assert not is_valid_web_url("javascript:alert(1)")
    assert not is_valid_web_url("data:text/html,<script>alert(1)</script>")

    payload = "<script>alert(1)</script>%_' OR 1=1--"
    with app.app_context():
        db.create_all()

    with app.test_client() as client:
        response = client.get("/apps", query_string={"q": payload})
        assert response.status_code == 200
        assert payload.encode() not in response.data
        assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in response.data

        policy = response.headers["Content-Security-Policy"]
        for directive in (
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ):
            assert directive in policy
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"

        error = client.get("/_security-test/exception")
        assert error.status_code == 500
        assert b"DO_NOT_EXPOSE" not in error.data
        assert b"Traceback" not in error.data
        assert "no-store" in error.headers["Cache-Control"]

        for confidential_path in ("/.env", "/.git/config", "/static/../.env"):
            hidden = client.get(confidential_path)
            assert hidden.status_code == 404
            assert b"DATABASE_URL" not in hidden.data

    print("Web security checks passed.")


if __name__ == "__main__":
    main()
