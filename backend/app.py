from flask import Flask, render_template, request, redirect, flash, url_for, jsonify, session
import firebase_admin
from firebase_admin import credentials, firestore, auth
import re
import requests

app = Flask(__name__)
app.secret_key = "FTTRDRE%$drcyvtyfF^%D%^DTYhbbyuB&^FFvyubhbuHUYG*&G&GYUHBBHJBK87^&^76&T%^R%DERFCCVGVTYf^TFR^tyfvgvf6t6tf67fvg^FF&G*Vgvccved34W#W$%"  # paste you're secret key here 🤫 or use .env

# Firebase Init
cred = credentials.Certificate('firebase_key.json')  # create this file and paste firebase keys
firebase_admin.initialize_app(cred)
db = firestore.client()

def get_client_ip():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip:
        ip = ip.split(',')[0].strip()
    if ip.startswith(('127.', '192.', '10.', '172.', '::1', 'localhost')):
        try:
            ip = requests.get('https://api.ipify.org').text.strip()
        except:
            ip = '8.8.8.8'
    return ip or '8.8.8.8'

@app.route('/')
def home():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Add logout route for convenience:
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Detect client IP and country
    ip = get_client_ip()
    country = "United States"
    country_code = "+1"

    try:
        res = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        geo = res.json()
        if geo.get("success"):
            country = geo.get("country", country)
            country_code = f"+{geo.get('calling_code', '1')}"
    except Exception as e:
        print("Geo IP detection failed:", e)

    # If POST is JSON (from Firebase client registration)
    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        id_token = data.get("idToken")

        if not id_token:
            return jsonify({"success": False, "message": "Missing ID token."}), 400

        try:
            # Verify Firebase token and create session
            decoded_token = auth.verify_id_token(id_token)
            session['user_id'] = decoded_token['uid']
            session['email'] = decoded_token.get('email')  # optional
            return jsonify({"success": True})
        except Exception as e:
            print("ID token verification failed:", str(e))
            return jsonify({"success": False, "message": "Invalid ID token"}), 401

    # If GET, render registration page
    return render_template('register.html', country=country, country_code=country_code)



@app.route("/google-signin", methods=["POST"])
def google_signin():
    data = request.get_json()
    id_token = data.get("idToken")

    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token["uid"]

        # Store user session (adjust as needed)
        session["user_id"] = uid

        return jsonify({ "success": True })
    except Exception as e:
        print("Google Sign-In verification failed:", e)
        return jsonify({ "success": False, "message": "Invalid token" }), 401


@app.route('/phone-signin', methods=['POST'])
def phone_signin():
    try:
        id_token = request.json.get('idToken')
        decoded_token = auth.verify_id_token(id_token)

        uid = decoded_token['uid']
        phone = decoded_token.get('phone_number')

        # Save or update user in Firestore
        db.collection('users').document(uid).set({
            'phone': phone,
            'provider': 'phone'
        }, merge=True)

        return jsonify({'success': True})

    except Exception as e:
        print("Phone sign-in error:", e)
        return jsonify({'success': False, 'message': str(e)}), 401



@app.route('/login')
def login():
    # IP and country detection
    ip = get_client_ip()
    country = "United States"
    country_code = "+1"

    try:
        res = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        geo = res.json()
        if geo.get("success"):
            country = geo.get("country", country)
            country_code = f"+{geo.get('calling_code', '1')}"
    except Exception as e:
        print("Geo IP detection failed:", e)

    return render_template('login.html', country=country, country_code=country_code)


@app.route('/login-email', methods=['POST'])
def login_email():
    try:
        id_token = request.json.get('idToken')
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        email = decoded_token.get('email')

        # Save or update user in Firestore
        db.collection('users').document(uid).set({
            'email': email,
            'provider': 'email'
        }, merge=True)

        # Set session
        session['user_id'] = uid
        return jsonify({'success': True})

    except Exception as e:
        print("Email sign-in error:", e)
        return jsonify({'success': False, 'message': str(e)}), 401


@app.route('/login-phone', methods=['POST'])
def login_phone():
    try:
        id_token = request.json.get('idToken')
        decoded_token = auth.verify_id_token(id_token)

        uid = decoded_token['uid']
        phone = decoded_token.get('phone_number')

        db.collection('users').document(uid).set({
            'phone': phone,
            'provider': 'phone'
        }, merge=True)

        session['user_id'] = uid
        return jsonify({'success': True})

    except Exception as e:
        print("Phone sign-in error:", e)
        return jsonify({'success': False, 'message': str(e)}), 401


@app.route('/forgot-password')
def forgot_password():
    error = request.args.get('error')
    success = request.args.get('success')

    if error:
        flash(error, 'error')
    if success:
        flash(success, 'success')

    return render_template('forgotpassword.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')



@app.route('/pomodoro')
def pomodoro():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('pomodoro.html')




@app.route('/countdown')
def countdown():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('countdown.html')






if __name__ == '__main__':
    app.run(debug=True)
