import re

with open('api/auth_routes.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Add send_login_notification function
login_mail_func = '''
def send_login_notification(user_name: str, user_email: str, ip_address: str) -> bool:
    """Send an email notification to the admin on new login."""
    recipients = _smtp_recipients()
    if not settings.SMTP_HOST or not settings.SMTP_FROM or not recipients:
        return False

    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = MIMEMultipart('alternative')
        msg['From'] = formataddr(("ThreatIntel TIP", settings.SMTP_FROM))
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = f"🔒 User Login: ThreatIntel TIP — {user_name}"
        safe_name = html.escape(user_name)
        safe_email = html.escape(user_email)
        safe_ip = html.escape(ip_address)

        text_body = f"""User logged into ThreatIntel Threat Intelligence Platform.

Name: {user_name}
Email: {user_email}
IP Address: {ip_address}
Time: {now} IST"""

        html_body = f"""<html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:20px">
<div style="max-width:500px;margin:0 auto;background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px">
  <h2 style="color:#00d4ff;margin-top:0">🔒 User Login Detected</h2>
  <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:16px">
    <tr><td style="padding:8px 0;color:#8b949e;width:80px">Name</td><td style="color:#e6edf3;font-weight:bold">{safe_name}</td></tr>
    <tr><td style="padding:8px 0;color:#8b949e">Email</td><td style="color:#e6edf3">{safe_email}</td></tr>
    <tr><td style="padding:8px 0;color:#8b949e">IP Address</td><td style="color:#e6edf3">{safe_ip}</td></tr>
    <tr><td style="padding:8px 0;color:#8b949e">Time</td><td style="color:#e6edf3">{now} IST</td></tr>
  </table>
</div>
</body></html>"""

        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))

        if settings.SMTP_USE_SSL:
            server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.SMTP_TIMEOUT)
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.SMTP_TIMEOUT)

        with server:
            server.set_debuglevel(0)
            server.ehlo()
            if settings.SMTP_USE_TLS and not settings.SMTP_USE_SSL:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg, from_addr=settings.SMTP_FROM, to_addrs=recipients)
        return True
    except Exception as e:
        logger.error(f"Failed to send login email: {e}")
        return False
'''

text = text.replace('def hash_password(password: str) -> str:', login_mail_func + '\ndef hash_password(password: str) -> str:')

# Update login route signature to take background_tasks
text = text.replace('async def login(req: LoginRequest, request: Request):', 'async def login(req: LoginRequest, request: Request, background_tasks: BackgroundTasks):')

# Add background task triggering to login route
text = text.replace('await db.log_user_activity(user[\'id\'], "LOGIN", f"User logged in from {request.client.host}", request.client.host)', 
'''await db.log_user_activity(user['id'], "LOGIN", f"User logged in from {request.client.host}", request.client.host)
    
    # Send login email notification
    background_tasks.add_task(send_login_notification, user["name"], user["email"], request.client.host)''')

with open('api/auth_routes.py', 'w', encoding='utf-8') as f:
    f.write(text)
print('Patched auth_routes.py')
