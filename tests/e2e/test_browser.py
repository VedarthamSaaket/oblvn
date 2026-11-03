import json
import re
import time

import pyotp
import pytest

from tests.live_server import LiveServer, configured

pytestmark = [pytest.mark.e2e, pytest.mark.skipif(not configured(), reason=".env.test is not configured")]
EMAIL = "browser@e2e.test"
PW = "Browser-Test-Pass-9!"
STATE = {}
SENSITIVE = ("refresh_token", "password_hash", "token_hash", "mfa_secret", "recovery_codes\":[\"", "SECRETPSID")


@pytest.fixture(scope="module")
def server():
    s = LiveServer(serve_frontend=True).start()
    yield s
    s.stop()


@pytest.fixture(scope="module")
def browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        yield b
        b.close()


@pytest.fixture(scope="module")
def page(browser, server):
    context = browser.new_context(viewport={"width": 1440, "height": 900}, accept_downloads=True)
    pg = context.new_page()
    pg.captured = {"responses": [], "urls": [], "console_errors": []}

    def on_response(resp):
        pg.captured["urls"].append(resp.url)
        if "/api/" in resp.url:
            try:
                pg.captured["responses"].append((resp.url, resp.text()))
            except Exception:
                pass
    pg.on("response", on_response)
    pg.on("websocket", lambda ws: pg.captured["urls"].append(ws.url))
    pg.on("console", lambda m: pg.captured["console_errors"].append(m.text) if m.type == "error" else None)
    yield pg
    context.close()


def _fill(page, selector, value):
    page.locator(selector).first.fill(value)


def test_register_lands_on_dashboard(page, server):
    page.goto(f"{server.url}/app/register")
    _fill(page, "input[type=email]", EMAIL)
    _fill(page, "input[type=password]", PW)
    page.get_by_role("button", name=re.compile("Create Account")).click()
    page.wait_for_url(re.compile(r"/app/dashboard"), timeout=20000)
    assert page.locator("text=OBLVN").first.is_visible()


def test_sign_out_and_sign_in(page, server):
    page.get_by_role("button", name="Sign Out").click()
    page.wait_for_url(re.compile(r"/app/login"), timeout=15000)
    _fill(page, "input[type=email]", EMAIL)
    _fill(page, "input[type=password]", "Wrong-Pass-9!")
    page.get_by_role("button", name=re.compile("Sign In")).first.click()
    page.wait_for_selector("text=Incorrect email or password", timeout=10000)
    _fill(page, "input[type=password]", PW)
    page.get_by_role("button", name=re.compile("Sign In")).first.click()
    page.wait_for_url(re.compile(r"/app/dashboard"), timeout=15000)


def test_every_page_renders(page, server):
    for path, text in (("devices", "OBLVN"), ("jobs", "OBLVN"), ("certificates", "Proof of"),
                       ("audit", "OBLVN"), ("anomalies", "Threat"), ("org", "OBLVN"), ("settings", "Two-Factor")):
        page.goto(f"{server.url}/app/{path}")
        page.wait_for_selector(f"text={text}", timeout=15000)
        assert "/app/login" not in page.url, path


def test_wipe_job_progress_and_certificate(page, server):
    folder = server.wipe_root / "e2e-ledger"
    folder.mkdir()
    for i in range(150):
        (folder / f"batch-{i:03d}.csv").write_bytes(b"account,balance\n1,100\n" * 50)
    target = folder
    job = page.evaluate("""async (path) => {
        const r = await fetch('/api/jobs', {method: 'POST', credentials: 'include',
            headers: {'Content-Type': 'application/json', Authorization: `Bearer ${localStorage.getItem('oblvn_token')}`},
            body: JSON.stringify({method: 'binary_overwrite', standard: 'nist_800_88', device_serial: `file:${path}`})})
        return {status: r.status, body: await r.json()}
    }""", str(target))
    assert job["status"] == 201, job
    page.goto(f"{server.url}/app/jobs/{job['body']['id']}")
    page.wait_for_selector("text=Wipe complete", timeout=60000)
    page.wait_for_selector("text=Download Certificate PDF", timeout=60000)
    with page.expect_download(timeout=30000) as dl:
        page.get_by_role("button", name="Download Certificate PDF").click()
    path = dl.value.path()
    assert open(path, "rb").read(4) == b"%PDF"
    page.goto(f"{server.url}/app/certificates")
    page.wait_for_selector("text=Folder Wipe — e2e-ledger (150 files)", timeout=15000)


def test_anomaly_feedback_button(page, server):
    page.goto(f"{server.url}/app/anomalies")
    page.get_by_role("button", name="All").click()
    page.wait_for_selector("text=new operator first wipe", timeout=15000)
    page.get_by_role("button", name="False alarm").first.click()
    page.wait_for_selector("text=Marked as a false alarm", timeout=10000)


def test_enable_two_factor_then_sign_in_with_code(page, server):
    page.goto(f"{server.url}/app/settings")
    row = page.locator("div", has_text=re.compile("^Two-Factor Authentication")).last
    row.scroll_into_view_if_needed()
    page.locator("text=Disabled").first.wait_for(timeout=10000)
    toggle = page.locator("xpath=//div[contains(., 'Require a code from an authenticator app')]/following-sibling::div//label/div").first
    toggle.click()
    key_text = page.wait_for_selector("text=/enter this key: [A-Z2-7]+/", timeout=15000).inner_text()
    secret = re.search(r"enter this key: ([A-Z2-7]+)", key_text).group(1)
    STATE["totp"] = secret
    page.fill("input[placeholder='6-digit code']", pyotp.TOTP(secret).now())
    page.get_by_role("button", name="Confirm").click()
    page.wait_for_selector("text=Save these recovery codes now", timeout=15000)
    page.get_by_role("button", name="Sign Out", exact=True).click()
    page.wait_for_url(re.compile(r"/app/login"), timeout=15000)
    _fill(page, "input[type=email]", EMAIL)
    _fill(page, "input[type=password]", PW)
    page.get_by_role("button", name=re.compile("Sign In")).first.click()
    page.wait_for_selector("text=Two-Factor Check", timeout=15000)
    assert "/app/dashboard" not in page.url
    time.sleep(1)
    page.locator("input").first.fill(pyotp.TOTP(secret).at(time.time() + 30))
    page.get_by_role("button", name=re.compile("Verify")).click()
    page.wait_for_url(re.compile(r"/app/dashboard"), timeout=15000)


def test_session_survives_reload_through_the_refresh_cookie(page, server):
    page.evaluate("localStorage.setItem('oblvn_token', 'expired-or-garbage')")
    page.goto(f"{server.url}/app/jobs")
    page.wait_for_timeout(4000)
    assert "/app/login" not in page.url
    assert page.evaluate("localStorage.getItem('oblvn_token')") not in (None, "expired-or-garbage")
    assert page.evaluate("localStorage.getItem('oblvn_refresh')") is None
    cookies = {c["name"]: c for c in page.context.cookies()}
    assert cookies["oblvn_refresh"]["httpOnly"] is True and cookies["oblvn_refresh"]["sameSite"] == "Strict"


def test_sign_out_everywhere_revokes_other_sessions(page, server):
    import httpx
    other = httpx.Client(base_url=server.url, timeout=30)
    step = other.post("/api/auth/login", json={"email": EMAIL, "password": PW}).json()
    assert step["mfa_required"]
    enable = next(body for url, body in page.captured["responses"] if url.endswith("/api/auth/2fa/enable"))
    recovery = json.loads(enable)["recovery_codes"][0]
    session = other.post("/api/auth/2fa/login", json={"mfa_token": step["mfa_token"], "code": recovery}).json()
    token = {"Authorization": f"Bearer {session['access_token']}"}
    assert other.get("/api/auth/me", headers=token).status_code == 200
    page.goto(f"{server.url}/app/settings")
    page.get_by_role("button", name="Sign Out Everywhere").click()
    page.wait_for_url(re.compile(r"/app/login"), timeout=15000)
    assert other.get("/api/auth/me", headers=token).status_code == 401
    assert other.post("/api/auth/refresh").status_code == 401
    other.close()


def test_network_tab_never_shows_secrets(page):
    shown_once = ("/api/auth/2fa/enable", "/api/auth/2fa/setup")
    leaks = [(u, word) for u, body in page.captured["responses"] for word in SENSITIVE
             if word in body and not u.endswith(shown_once)]
    assert leaks == []
    token_urls = [u for u in page.captured["urls"] if "token=" in u and "/ws/" in u]
    assert token_urls == []
    assert any("/ws/jobs/" in u and "ticket=" in u for u in page.captured["urls"])


def test_no_console_errors_from_the_app(page):
    real = [e for e in page.captured["console_errors"]
            if "401" not in e and "Failed to load resource" not in e and "favicon" not in e]
    assert real == [], json.dumps(real, indent=1)
