# app.py
import os
from waitress import serve

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import datetime
import config
import email_alert
import fraud_detection
import os
#import sms_alert
import random
import string

# Continue inside app.py
import time

# Flask App Initialization
app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('database/user.db')
    conn.row_factory = sqlite3.Row
    return conn

# Home → Login Page
# app.py

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_phone = request.form['email_or_phone']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (email_or_phone, email_or_phone)).fetchone()

        if user:
            if user['is_blocked']:
                if user['unblock_time'] and int(time.time()) < user['unblock_time']:
                    conn.close()
                    flash("Account temporarily blocked. Try again later.", "error")
                    return render_template('login.html')
                else:
                    conn.execute('UPDATE users SET is_blocked = 0, unblock_time = NULL WHERE id = ?', (user['id'],))
                    conn.commit()

            user_agent = request.headers.get('User-Agent')
            ip_address = request.remote_addr

            trusted = conn.execute('''
                SELECT * FROM trusted_locations 
                WHERE email = ? AND ip = ? AND added_time > datetime("now", "-30 days")
            ''', (user['email'], ip_address)).fetchone()

            if not trusted:
                email_alert.send_trust_location_email(user['email'], ip_address, user_agent)
                flash('⚠️ Login from a new device or IP. Verification email sent.', 'warning')
            else:
                session.pop('new_location', None)
                session.pop('new_ip', None)

            if user['device_info']:
                if user_agent != user['device_info'] or ip_address != user['last_ip']:
                    email_alert.send_new_device_alert(user['email'], user_agent, ip_address)
            else:
                conn.execute('UPDATE users SET device_info = ?, last_ip = ? WHERE id = ?', (user_agent, ip_address, user['id']))
                conn.commit()

            conn.close()

            if check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['user_email'] = user['email']
                session['user_phone'] = user['phone']
                flash('Login Successful!', 'success')
                session.pop('pending_receiver', None)
                session.pop('pending_amount', None)
                session.pop('otp_retries', None)
                return redirect(url_for('dashboard'))
            else:
                conn.close()
                flash('Invalid Email/Phone or Password!', 'error')

    return render_template('login.html')
@app.route('/trust_location')
def trust_location():
    email = request.args.get('email')
    ip = request.args.get('ip')

    if not email or not ip:
        flash('Invalid trust request.', 'error')
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('INSERT INTO trusted_locations (email, ip) VALUES (?, ?)', (email, ip))
    conn.commit()
    conn.close()

    flash('✅ Location trusted successfully via email verification.', 'success')
    return redirect(url_for('login'))


def generate_captcha():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))

@app.route('/verify_login_otp', methods=['GET', 'POST'])
def verify_login_otp():
    if 'temp_user_email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if email_alert.verify_otp(session['temp_user_email'], entered_otp):
            # OTP correct → promote session
            session['user_id'] = session.pop('temp_user_id')
            session['user_name'] = session.pop('temp_user_name')
            session['user_email'] = session.pop('temp_user_email')
            session.pop('otp_retries', None)

            flash('✅ Login Successful with OTP verification!', 'success')
            return redirect(url_for('dashboard'))
        else:
            session['otp_retries'] += 1
            if session['otp_retries'] >= 3:
                flash('❌ Too many failed OTP attempts. Please login again.', 'error')
                session.clear()
                return redirect(url_for('login'))
            else:
                flash(f'Wrong OTP! Attempts left: {3 - session["otp_retries"]}', 'error')

    return render_template('verify_login_otp.html')


# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        captcha_entered = request.form['captcha_entered']
        captcha_real = session.get('captcha_real')

        if captcha_entered != captcha_real:
            flash('Captcha mismatch. Please try again.', 'error')
            # Regenerate captcha on mismatch
            new_captcha = generate_captcha()
            session['captcha_real'] = new_captcha
            return render_template('register.html', captcha=new_captcha)

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html', captcha=session.get('captcha_real', ''))

        import re
        if (len(password) < 8 or
            not re.search(r'[A-Z]', password) or
            not re.search(r'\d', password) or
            not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
            flash('Password must contain minimum 8 chars, 1 uppercase, 1 number, 1 special character.', 'error')
            return render_template('register.html', captcha=session.get('captcha_real', ''))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (email, phone)).fetchone()
        if existing_user:
            conn.close()
            flash('Account already exists. Please login.', 'error')
            return redirect(url_for('login'))
        else:
            conn.execute('INSERT INTO users (name, email, phone, password, balance, is_blocked) VALUES (?, ?, ?, ?, ?, ?)',
                         (name, email, phone, hashed_password, 1000000, 0))
            conn.commit()
            conn.close()
            flash('Registration Successful! Please login.', 'success')
            return redirect(url_for('login'))

    # For GET request: show new captcha
    captcha = generate_captcha()
    session['captcha_real'] = captcha
    return render_template('register.html', captcha=captcha)


# Dashboard Page
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Connect to transaction.db to check frauds
    conn_txn = sqlite3.connect('database/transaction.db')
    conn_txn.row_factory = sqlite3.Row
    frauds = conn_txn.execute('''
        SELECT COUNT(*) AS count FROM transactions
        WHERE sender_email = ? AND status = 'fraud'
    ''', (session['user_email'],)).fetchone()
    conn_txn.close()

    fraud_count = frauds['count'] if frauds else 0

    return render_template('dashboard.html', username=session['user_name'], fraud_count=fraud_count)

# Profile Page
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    return render_template('profile.html', user=user)

# Update Profile Page
@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    if request.method == 'POST':
        new_name = request.form['name']
        new_phone = request.form['phone']

        conn.execute('UPDATE users SET name = ?, phone = ? WHERE id = ?', (new_name, new_phone, session['user_id']))
        conn.commit()
        conn.close()

        session['user_name'] = new_name
        session['user_phone'] = new_phone

        flash('Profile Updated Successfully!', 'success')
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('update_profile.html', user=user)

# Delete Account
@app.route('/delete_account')
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (session['user_id'],))
    conn.execute('DELETE FROM transactions WHERE sender_id = ? OR receiver_id = ?', (session['user_id'], session['user_id']))
    conn.commit()
    conn.close()

    session.clear()
    flash('Account deleted successfully.', 'success')
    return redirect(url_for('login'))
# New Transaction Page
@app.route('/new_transaction', methods=['GET', 'POST'])
def new_transaction():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        receiver_input = request.form['receiver']
        amount = int(request.form['amount'])

        conn = get_db_connection()
        receiver = conn.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (receiver_input, receiver_input)).fetchone()

        if not receiver:
            flash('Receiver not found!', 'error')
            return redirect(url_for('new_transaction'))

        session['pending_receiver'] = receiver['email']
        session['pending_amount'] = amount
        session['otp_retries'] = 0

        print("✅ Receiver found:", receiver['email'])  # Debug
        print("Sending OTP to:", session['user_email'])

        email_alert.send_otp(session['user_email'])  # Make sure this function doesn't crash silently

        flash('OTP sent to your email. Please verify to proceed.', 'info')
        return redirect(url_for('otp_verify'))

    return render_template('new_transaction.html')

# OTP Verify Page
@app.route('/otp_verify', methods=['GET', 'POST'])
def otp_verify():
    if 'user_id' not in session or 'pending_receiver' not in session or 'pending_amount' not in session:
        flash("Session expired. Start transaction again.", "error")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        receiver = session['pending_receiver']
        amount = session['pending_amount']

        if email_alert.verify_otp(session['user_email'], entered_otp):
            print("✅ OTP verified successfully!")
            print("Receiver:", receiver)
            print("Amount:", amount)

            # Step 1: Update balances
            conn = get_db_connection()
            conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (amount, session['user_id']))
            conn.execute('UPDATE users SET balance = balance + ? WHERE email = ?', (amount, receiver))
            conn.commit()

            # Fetch updated sender balance for email
            sender_data = conn.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            conn.close()

            # Step 2: Email Notification
            time_now = datetime.datetime.now().strftime('%I:%M %p')
            sender_msg = f"₹{amount} debited to {receiver} at {time_now}\nRemaining Balance: ₹{sender_data['balance']}"
            receiver_msg = f"₹{amount} credited from {session['user_email']} at {time_now}"

            email_alert.send_generic_email(session['user_email'], "💸 SafeBank Debit Alert", sender_msg)
            email_alert.send_generic_email(receiver, "💰 SafeBank Credit Alert", receiver_msg)

            # Step 3: Fraud Detection
            conn_txn = sqlite3.connect('database/transaction.db')
            txn_count = conn_txn.execute('''
                SELECT COUNT(*) FROM transactions
                WHERE sender_email = ? AND time > datetime('now', '-60 seconds')
            ''', (session['user_email'],)).fetchone()[0]
            conn_txn.close()

            multiple_transfers = 1 if txn_count >= 3 else 0
            current_hour = datetime.datetime.now().hour
            otp_failures = session.get('otp_retries', 0)
            location_mismatch = 0  # optional: enhance later
            device_mismatch = 0    # optional: enhance later

            features = [amount, current_hour, location_mismatch, device_mismatch, multiple_transfers, otp_failures]
            fraud_label, fraud_score = fraud_detection.predict_fraud(features)

            # Step 4: Save to transaction DB
            conn_txn = sqlite3.connect('database/transaction.db')
            conn_txn.execute('''
                INSERT INTO transactions (sender_email, receiver_email, amount, time, status, fraud_score)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session['user_email'], receiver, amount, datetime.datetime.now(),
                  'fraud' if fraud_label == 1 else 'safe', fraud_score))
            conn_txn.commit()
            conn_txn.close()

            # Step 5: Session cleanup
            session.pop('pending_receiver', None)
            session.pop('pending_amount', None)
            session.pop('otp_retries', None)

            if fraud_label == 1:
                flash(f'⚠️ Transaction Done but Marked as Fraud! (Fraud Score: {fraud_score:.2f}%)', 'error')
            else:
                flash(f'✅ Transaction Successful! (Fraud Score: {fraud_score:.2f}%)', 'success')

            return redirect(url_for('transaction_success'))

        else:
            # Handle wrong OTP
            session['otp_retries'] += 1
            if session['otp_retries'] >= 3:
                unblock_time = int(time.time()) + (24 * 3600)
                conn = get_db_connection()
                conn.execute('UPDATE users SET is_blocked = 1, unblock_time = ? WHERE id = ?',
                             (unblock_time, session['user_id']))
                conn.commit()
                conn.close()

                email_alert.delete_otp(session['user_email'])
                session.clear()
                flash('Account temporarily blocked due to 3 wrong OTP entries. Try after 24 hours.', 'error')
                return redirect(url_for('login'))
            else:
                flash(f'Wrong OTP! Attempts left: {3 - session["otp_retries"]}', 'error')

    return render_template('otp_verify.html')


# Transaction Success Page
@app.route('/transaction_success')
def transaction_success():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('transaction_success.html')

# Transaction History
@app.route('/transaction_history')
def transaction_history():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Connect to transaction DB (not user DB!)
    conn = sqlite3.connect('database/transaction.db')
    conn.row_factory = sqlite3.Row

    transactions = conn.execute('''
        SELECT * FROM transactions 
        WHERE sender_email = ? OR receiver_email = ? 
        ORDER BY time DESC
    ''', (session['user_email'], session['user_email'])).fetchall()

    conn.close()

    return render_template('transaction_history.html', transactions=transactions)




# Check Balance
@app.route('/check_balance', methods=['GET', 'POST'])
def check_balance():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()

        print("Entered password:", entered_password)
        print("User hashed password:", user['password'])

        if user and check_password_hash(user['password'], entered_password):
            print("✅ Password matched")
            balance = user['balance']
            return render_template('check_balance.html', balance=balance)

        else:
            flash('Invalid password.', 'error')
            print("❌ Password mismatch")

    return render_template('check_balance.html', balance=None)

# Logout
@app.route('/logout')
def logout():
    session.pop('pending_receiver', None)
    session.pop('pending_amount', None)
    session.pop('otp_retries', None)

    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Error Page for Blocked User (optional)
@app.route('/block')
def block():
    return render_template('block.html')

# Main
if __name__ == '__main__':
    if not os.path.exists('database/user.db'):
        print("❌ Database not found! Please run database_setup.py first.")
    else:
        print("✅ Starting SafeBank with Waitress...")
        serve(app, host='0.0.0.0', port=10000)