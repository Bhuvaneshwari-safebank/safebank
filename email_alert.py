import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import config

# ✅ Temporary in-memory OTP store
otp_storage = {}

def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))

def send_otp(receiver_email):
    """Send OTP to the user's registered email"""
    otp = generate_otp()
    otp_storage[receiver_email] = otp

    msg = MIMEMultipart()
    msg['From'] = config.SMTP_EMAIL
    msg['To'] = receiver_email
    msg['Subject'] = "SafeBank OTP Verification Code"

    body = f"""
    Dear User,

    Your OTP for SafeBank transaction is: {otp}

    Please do not share this OTP with anyone.

    Regards,
    SafeBank Team
    """

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls()
        server.login(config.SMTP_EMAIL, config.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"✅ OTP sent successfully to {receiver_email}")
        return True
    except Exception as e:
        print(f"❌ Error sending OTP: {e}")
        return False

def send_trust_location_email(email, ip, user_agent):
    subject = "🚨 SafeBank Alert: Suspicious Login from New Device/IP"
    body = f"""
    Hello,

    A login was detected from a new browser or IP.

    - Browser: {user_agent}
    - IP Address: {ip}

    If this was **NOT you**, please change your password immediately.

    If it was you, you can trust this location by clicking below:
    ✅ https://your-domain.com/trust_location?email={email}&ip={ip}

    Stay Safe,
    SafeBank Security Team
    """
    msg = MIMEMultipart()
    msg['From'] = config.SMTP_EMAIL
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls()
        server.login(config.SMTP_EMAIL, config.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"✅ Trust location email sent to {email}")
    except Exception as e:
        print(f"❌ Error sending trust location email: {e}")


def verify_otp(receiver_email, entered_otp):
    """Verify entered OTP matches"""
    if receiver_email in otp_storage:
        if otp_storage[receiver_email] == entered_otp:
            del otp_storage[receiver_email]
            return True
    return False


def delete_otp(receiver_email):
    """Clear OTP manually (example: after 3 wrong tries)"""
    if receiver_email in otp_storage:
        del otp_storage[receiver_email]

def send_generic_email(receiver_email, subject, body):
    """Send a custom email (used for transaction alert)"""
    msg = MIMEMultipart()
    msg['From'] = config.SMTP_EMAIL
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls()
        server.login(config.SMTP_EMAIL, config.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"✅ Email sent to {receiver_email}")
    except Exception as e:
        print(f"❌ Error sending email to {receiver_email}: {e}")

def send_new_device_alert(receiver_email, device_info, ip_address):
    """Send alert email if new device or IP address detected"""
    subject = "⚠️ SafeBank Alert: New Device Login Detected"
    body = f"""
    Dear User,

    We detected a login from a new device or new IP address:

    - Browser Info: {device_info}
    - IP Address: {ip_address}

    If this was not you, please change your password immediately.

    Stay Safe,
    SafeBank Security Team
    """

    msg = MIMEMultipart()
    msg['From'] = config.SMTP_EMAIL
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT)
        server.starttls()
        server.login(config.SMTP_EMAIL, config.SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"✅ New Device/IP Alert Email Sent to {receiver_email}")
    except Exception as e:
        print(f"❌ Failed to send new device alert: {e}")



# Test
if __name__ == "__main__":
    email = "test@example.com"
    send_otp(email)
    print("Sent. Waiting for OTP check manually...")
