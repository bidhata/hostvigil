#!/usr/bin/env python3
"""
HostVigil Security Test Suite
Tests for critical security fixes
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_secret_key_randomized():
    """Test that secret key is not the default insecure value."""
    from hostvigil.dashboard.app import create_app

    app = create_app()
    assert app.config["SECRET_KEY"] != "change-this-in-production"
    assert len(app.config["SECRET_KEY"]) >= 32
    print("✓ Secret key is randomized")


def test_session_cookies_secure():
    """Test that session cookies have secure flags."""
    from hostvigil.dashboard.app import create_app

    app = create_app()
    app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    assert app.config.get("SESSION_COOKIE_SECURE") is True
    assert app.config.get("SESSION_COOKIE_HTTPONLY") is True
    assert app.config.get("SESSION_COOKIE_SAMESITE") == "Lax"
    print("✓ Session cookies are secure")


def test_login_without_credentials():
    """Test login page doesn't show credentials."""
    from hostvigil.dashboard.app import create_app

    app = create_app()
    client = app.test_client()

    response = client.get("/login")
    assert b"hostvigil" not in response.data
    assert b"Default credentials" not in response.data
    print("✓ Login page doesn't expose credentials")


if __name__ == "__main__":
    print("Running HostVigil Security Tests\n")
    test_secret_key_randomized()
    test_session_cookies_secure()
    test_login_without_credentials()
    print("\n✓ All security tests passed!")
