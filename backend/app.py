from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify, make_response
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os
import requests
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from functools import wraps
from firebase_admin import firestore

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")

# Google OAuth setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'access_type': 'offline',
        'prompt': 'consent',
    },
)


# Firebase Admin SDK init
if not firebase_admin._apps:
    cred = credentials.Certificate("focusly-97e22-firebase-adminsdk-fbsvc-897f36b6b9.json")
    firebase_admin.initialize_app(cred)

db = firestore.client()

# Redirect replace helper
def redirect_replace(target_url):
    return render_template('redirect_replace.html', target=target_url)

# No cache decorator
def nocache(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        response = make_response(view_func(*args, **kwargs))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return wrapper

def get_public_ip():
    try:
        return requests.get('https://api.ipify.org', timeout=2).text
    except Exception as e:
        print("❌ Failed to get public IP:", e)
        return None

@app.route('/')
@nocache
def home():
    if 'user' in session:
        return redirect_replace(url_for('dashboard'))
    return render_template("index.html")

@app.route('/login', methods=['GET'])
@nocache
def login():
    # Redirect if user is already logged in
    if 'user' in session:
        return redirect(url_for('dashboard'))

    # Get client IP, fallback to public IP if local/private IP detected
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip.split(',')[0].strip() if ip else None

    def is_private_ip(ip_address):
        private_prefixes = ('127.', '192.', '10.', '172.', 'localhost')
        return any(ip_address.startswith(prefix) for prefix in private_prefixes)

    if not ip or is_private_ip(ip):
        ip = get_public_ip() or '8.8.8.8'

    # Default geo info
    country = "United States"
    country_code = "+1"

    # Get geo info from external API
    try:
        res = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        geo = res.json()
        if geo.get("success"):
            country = geo.get("country", country)
            calling_code = geo.get('calling_code')
            if calling_code and calling_code.isdigit():
                country_code = f"+{calling_code}"
    except Exception as e:
        print("❌ Geo IP error:", e)

    # Firebase error code to friendly message mapping
    firebase_error_map = {
        "auth/user-not-found": "No user found with that email.",
        "auth/wrong-password": "Incorrect password.",
        "auth/invalid-email": "Please enter a valid email address.",
        "auth/too-many-requests": "Too many attempts. Please try again later.",
        "auth/invalid-login-credentials": "Invalid login credentials.",
    }

    # Check for query param error
    error = request.args.get("error")
    if error:
        # Convert Firebase error code to friendly message if possible
        friendly_msg = firebase_error_map.get(error, error)
        flash(friendly_msg, "error")

    # Handle flash messages stored in session (optional)
    if 'flash' in session:
        category, message = session.pop('flash')
        flash(message, category)

    return render_template("login.html", country=country, country_code=country_code)



@app.route('/login-client', methods=['POST'])
@nocache
def login_client():
    data = request.get_json()
    id_token = data.get('id_token')

    if not id_token:
        flash('Missing ID token.', 'error')
        return jsonify({"redirect": url_for('login')}), 400

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token.get('uid')
        email = decoded_token.get('email')

        if not email:
            flash('Email not found in token.', 'error')
            return jsonify({"redirect": url_for('login')}), 400

        session['user'] = {"email": email, "uid": uid}
        return jsonify({"redirect": url_for('dashboard')}), 200

    except Exception as e:
        print("❌ Firebase token verification failed:", e)
        flash('Invalid or expired token.', 'error')
        return jsonify({"redirect": url_for('login')}), 401




@app.route('/login-phone', methods=['POST'])
@nocache
def login_phone():
    data = request.get_json()
    id_token = data.get('id_token') if data else None

    if not id_token:
        return jsonify({"error": "Missing ID token"}), 400

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        phone_number = decoded_token.get('phone_number')
        uid = decoded_token.get('uid')

        if not phone_number:
            return jsonify({"error": "Phone number not found"}), 400

        session['user'] = {"phone": phone_number, "uid": uid}
        return jsonify({"message": "Login successful"}), 200

    except Exception as e:
        print("❌ Firebase token verification failed:", e)
        return jsonify({"error": "Invalid or expired token"}), 401




@app.route('/forgot-password')
def forgot_password():
    error = request.args.get('error')
    success = request.args.get('success')

    if error:
        flash(error, 'error')
    if success:
        flash(success, 'success')

    return render_template('forgotpassword.html')




@app.route('/register', methods=['GET', 'POST'])
@nocache
def register():
    if 'user' in session:
        return redirect_replace(url_for('dashboard'))

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    ip = ip.split(',')[0].strip() if ip else '8.8.8.8'
    if ip.startswith(('127.', '192.', '10.', '172.', '::1', 'localhost')):
        ip = get_public_ip() or '8.8.8.8'

    country = "United States"
    country_code = "+1"
    try:
        res = requests.get(f"https://ipwho.is/{ip}", timeout=3)
        geo = res.json()
        if geo.get("success"):
            country = geo.get("country", country)
            country_code = f"+{geo.get('calling_code', '1')}"
    except Exception as e:
        print("❌ Geo IP error:", e)

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for('register'))

        if password != password_confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))

        try:
            user_record = firebase_auth.create_user(email=email, password=password)
            session['user'] = {"email": user_record.email, "uid": user_record.uid}
            return redirect_replace(url_for('dashboard'))

        except firebase_auth.EmailAlreadyExistsError:
            flash("Email already in use. Please sign in instead.", "error")
            return redirect(url_for('register'))

        except Exception as e:
            print("❌ Error creating user:", e)
            flash("Failed to create account. Please try again.", "error")
            return redirect(url_for('register'))

    return render_template("register.html", country=country, country_code=country_code)


@app.route('/register-phone', methods=['POST'])
@nocache
def register_phone():
    id_token = request.json.get('idToken')
    if not id_token:
        return jsonify({"error": "Missing idToken"}), 400

    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        phone_number = decoded_token.get('phone_number')
        if not phone_number:
            return jsonify({"error": "Phone number missing in token"}), 400

        session['user'] = {"phone": phone_number, "uid": uid}
        return jsonify({"message": "User registered/updated successfully"}), 200
    except Exception as e:
        print("Firebase token verification failed:", e)
        return jsonify({"error": "Invalid or expired token"}), 401


@app.route('/dashboard')
@nocache
def dashboard():
    user = session.get('user')
    if not user:
        return redirect_replace(url_for('login'))

    # 🔥 Generate Firebase custom token
    try:
        custom_token = firebase_auth.create_custom_token(user["uid"])
        return render_template("dashboard.html", user=user, token=custom_token.decode("utf-8"))
    except Exception as e:
        print("❌ Error generating Firebase custom token:", e)
        return redirect_replace(url_for('logout'))


@app.route('/auth/google')
@nocache
def auth_google():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
@nocache
def auth_callback():
    token = google.authorize_access_token()
    user_info = google.get('https://www.googleapis.com/oauth2/v3/userinfo').json()

    user_id = user_info.get('sub')
    email = user_info.get('email')
    name = user_info.get('name')
    picture = user_info.get('picture')

    session['user'] = {
        "uid": user_id,
        "email": email,
        "name": name,
        "picture": picture
    }

    # Store/update user in Firestore
    db.collection('users').document(user_id).set({
        'email': email,
        'name': name,
        'picture': picture,
        'last_login': firestore.SERVER_TIMESTAMP
    }, merge=True)

    # 🔥 Create Firebase custom token
    custom_token = firebase_auth.create_custom_token(user_id)

    # Pass to dashboard via URL
    return redirect(url_for('dashboard', token=custom_token.decode('utf-8')))


from flask import Flask, render_template, request, redirect, url_for
from datetime import timedelta
timer_minutes = 25
timer_seconds = 0
mode = 'pomodoro'  # or 'short_break', 'long_break'

@app.route('/pomodoro', methods=['GET', 'POST'])
def pomodoro():
    global timer_minutes, timer_seconds, mode

    if request.method == 'POST':
        action = request.form.get('action')
        selected_mode = request.form.get('mode')

        if selected_mode in ['pomodoro', 'short_break', 'long_break']:
            mode = selected_mode
            if mode == 'pomodoro':
                timer_minutes, timer_seconds = 25, 0
            elif mode == 'short_break':
                timer_minutes, timer_seconds = 5, 0
            elif mode == 'long_break':
                timer_minutes, timer_seconds = 15, 0

        if action == 'reset':
            if mode == 'pomodoro':
                timer_minutes, timer_seconds = 25, 0
            elif mode == 'short_break':
                timer_minutes, timer_seconds = 5, 0
            elif mode == 'long_break':
                timer_minutes, timer_seconds = 15, 0

        # Note: start/pause won't do anything here without JS or background task

        return redirect(url_for('pomodoro'))

    timer_display = f"{timer_minutes:02d}:{timer_seconds:02d}"
    return render_template('pomodoro.html', timer=timer_display, mode=mode)

@app.route('/pomodoro-popup')
def pomodoro_popup():
    return render_template('pomodoro-popup.html')

@app.route('/countdown')
def countdown():
    return render_template('countdown.html')

@app.route('/logout')
@nocache
def logout():
    session.pop('user', None)
    return redirect_replace(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)