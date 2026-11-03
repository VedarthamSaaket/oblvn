import html
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from backend.config import config

TEMPLATES = {
    "verify_email": ("Confirm your OBLVN account", "Confirm your email",
                     "Confirm this address to activate your OBLVN account.", "Confirm email", "24 hours"),
    "reset_password": ("Reset your OBLVN password", "Reset your password",
                       "Someone asked to reset the password for this OBLVN account. If it was not you, ignore this email.",
                       "Set a new password", "1 hour"),
    "invite": ("You have been invited to OBLVN", "You have been invited",
               "You have been invited to join {org} on OBLVN as {role}. Set a password to activate your account.",
               "Accept invite", "7 days"),
}


def configured() -> bool:
    return bool(config.SMTP_HOST and config.SMTP_FROM)


def render(kind: str, link: str, **context) -> tuple[str, str, str]:
    subject, title, body, button, ttl = TEMPLATES[kind]
    body = body.format(**{k: html.escape(str(v)) for k, v in context.items()})
    text = f"{title}\n\n{html.unescape(body)}\n\n{button}: {link}\n\nThis link expires in {ttl}.\n\nOBLVN"
    page = f"""<!doctype html><html><body style="margin:0;background:#1a2218;padding:40px 0;font-family:Georgia,serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center">
<table role="presentation" width="520" cellpadding="0" cellspacing="0" style="background:#1a2218;border:1px solid rgba(240,235,224,0.08);">
<tr><td style="padding:28px 36px;border-bottom:1px solid rgba(240,235,224,0.06);font-family:Georgia,serif;font-weight:900;font-size:22px;color:#f5e6c8;letter-spacing:-0.02em;">OBLVN</td></tr>
<tr><td style="padding:36px;">
<div style="font-family:'Courier New',monospace;font-size:9px;letter-spacing:0.28em;text-transform:uppercase;color:rgba(240,235,224,0.35);margin-bottom:18px;">{html.escape(title)}</div>
<div style="font-family:Georgia,serif;font-size:15px;line-height:1.7;color:#f5e6c8;margin-bottom:28px;">{body}</div>
<a href="{html.escape(link)}" style="display:inline-block;font-family:'Courier New',monospace;font-size:10px;letter-spacing:0.22em;text-transform:uppercase;color:#1a2218;background:#f5e6c8;padding:12px 28px;text-decoration:none;box-shadow:3px 3px 0 #4a5442;">{html.escape(button)}</a>
<div style="font-family:'Courier New',monospace;font-size:9px;color:rgba(240,235,224,0.3);margin-top:28px;line-height:1.8;">This link expires in {ttl}.<br>{html.escape(link)}</div>
</td></tr></table></td></tr></table></body></html>"""
    return subject, text, page


def send(to: str, kind: str, link: str, **context) -> bool:
    subject, text, page = render(kind, link, **context)
    if not configured():
        print(f"[MAIL] SMTP not configured; {kind} link for {to}: {link}")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((config.SMTP_FROM_NAME, config.SMTP_FROM))
    msg["To"] = to
    msg["Message-ID"] = make_msgid(domain=config.SMTP_FROM.split("@")[-1])
    msg.set_content(text)
    msg.add_alternative(page, subtype="html")
    context_ssl = ssl.create_default_context()
    if config.SMTP_SSL:
        server = smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=context_ssl, timeout=20)
    else:
        server = smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20)
    try:
        if not config.SMTP_SSL and config.SMTP_STARTTLS:
            server.starttls(context=context_ssl)
        if config.SMTP_USER:
            server.login(config.SMTP_USER, config.SMTP_PASSWORD)
        server.send_message(msg)
    finally:
        server.quit()
    return True
