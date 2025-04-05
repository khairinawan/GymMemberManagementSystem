from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import sqlite3
import bcrypt
from functools import wraps
import pyotp
import qrcode
import io
import base64
import logging
import os

app = Flask(__name__)
app.secret_key = os.urandom(32).hex()

# 🔹 Session Security Configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Enable this if using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 600  # Auto logout after 10 minutes for example

DATABASE = 'members.db'

# 🔹 Logger for security events
logging.basicConfig(filename='security.log', level=logging.WARNING)

def get_db():
    """Connect to SQLite Database"""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, check_same_thread=False)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.before_request
def create_tables():
    """Ensure necessary tables exist in the database before handling requests"""
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                )''')
    db.commit()

# 🔹 User Storage (Passwords are now hashed)
USERS = {
    "staff": {"password": bcrypt.hashpw("staffpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
              "role": "staff", "mfa_secret": pyotp.random_base32()},
    "member": {"password": bcrypt.hashpw("memberpass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
               "role": "member"},
    "pakkarim": {"password": bcrypt.hashpw("karim".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'),
                 "role": "staff", "mfa_secret": pyotp.random_base32()}
}

# 🔹 Secure decorator for login requirement
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 🔹 Secure decorator for staff-only access
def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session.get('role') != 'staff':
            return redirect(url_for('dashboard'))  # Redirect to dashboard instead of login
        return f(*args, **kwargs)
    return decorated_function

# 🔹 Login Route with Password Hashing
@app.route('/', methods=['GET', 'POST'])
def login():
    """Login Route"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Fetch user from USERS dictionary (no new database table)
        user = USERS.get(username)

        if user:
            print(f"🔹 Stored Hash for {username}: {user['password']}")  #Print stored hash
            hashed_password = user['password'].encode('utf-8')
            input_password = password.encode('utf-8')
            print(f"🔹 User Input Password: {password}")  #Print input password
            
            # Verify password with bcrypt
            if bcrypt.checkpw(input_password, hashed_password):
                session.clear()
                session['user'] = username
                session['role'] = user['role']
                session['mfa_verified'] = False  # Reset MFA status after login
                session.permanent = True  # Keep session active
                session.modified = True  # Ensure changes are applied

            if user['role'] == 'staff':
                return redirect(url_for('mfa'))  # 🔹 Redirect STAFF to MFA page first
            return redirect(url_for('dashboard'))  # 🔹 Redirect members to dashboard
        flash("Invalid username or password", "danger")

    return render_template('login.html')

# 🔹 MFA Route (Only for Staff)
@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    """MFA Verification Page for Staff"""
    if 'user' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))  # Ensure only logged-in users can access

    user = USERS.get(session['user'])
    if not user:
        return redirect(url_for('login'))

    totp = pyotp.TOTP(user['mfa_secret'])

    if request.method == 'POST':
        otp = request.form.get('otp')
        if totp.verify(otp):
            session['mfa_verified'] = True  # MFA passed
            session.permanent = True
            session.modified = True
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid OTP, try again", "danger")

    return render_template('mfa.html')

# 🔹 Logout Route (Clears Session)
@app.route('/logout')
def logout():
    session.clear()  # Clears all session data
    return redirect(url_for('login'))

# 🔹 Dashboard Route (Ensuring MFA is verified for staff)
@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard Route"""
    if session.get('role') == 'staff' and not session.get('mfa_verified'):
        flash("MFA required. Please verify first.", "warning")
        return redirect(url_for('mfa'))  # Redirect only staff

    role = session.get('role')  # Get role from session

    return render_template('dashboard.html', role=role)

# 🔹 Generate QR Code for MFA Setup
@app.route('/mfa/setup')
@staff_required
def mfa_setup():
    """Generate MFA QR Code for Google Authenticator"""
    print("🔹 DEBUG: Entered mfa_setup() function")

    user = USERS.get(session['user'])
    if not user:
        print("🔹 DEBUG: User not found in session")
        return redirect(url_for('dashboard'))

    print(f"🔹 DEBUG: Generating OTP for user {session['user']}") 
    
    totp = pyotp.TOTP(user['mfa_secret'])
    otp_uri = totp.provisioning_uri(name=session['user'], issuer_name="My Secure Flask App")

    print("OTP URI:", otp_uri)

    # Generate QR Code
    qr = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)
    img_base64 = base64.b64encode(img_io.getvalue()).decode()

    print("🔹 DEBUG: QR Code Generated (First 50 chars):", img_base64[:50])  # ✅ Debug QR output 

    return render_template('mfa_setup.html', qr_code=img_base64, redirect_to_mfa = True)

@app.route('/register_member', methods=['GET', 'POST'])
@staff_required
def register_member():
    """Only staff can register new members"""
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))  # Redirect after adding member

    return render_template('register_member.html')

# 🔹 Add Member (Restricted to Staff Only)
@app.route('/add_member', methods=['GET', 'POST'])
@staff_required
def add_member():
    """Only staff can add members"""
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html')

# 🔹 View Members (Restricted to Staff Only)
@app.route('/view_members')
@staff_required
def view_members():
    """Only staff can view members"""
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# 🔹 View Specific Member Classes
@app.route('/member/<int:member_id>/classes')
@login_required
def member_classes(member_id):
    """Members can view their registered classes"""
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                       "JOIN member_classes mc ON c.id = mc.class_id "
                       "WHERE mc.member_id = ?", [member_id])
    return render_template('member_classes.html', member=member, classes=classes)

# 🔹 Register Class for Member (Staff Only)
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
@staff_required
def register_class(member_id):
    """Staff can register members for classes"""
    classes = query_db("SELECT * FROM classes")

    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))

    return render_template('register_class.html', member_id=member_id, classes=classes)

@app.route('/view_classes')
@login_required
def view_classes():
    """Show a list of all available classes"""
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

@app.route('/delete_member/<int:member_id>', methods=['POST'])
@staff_required
def delete_member(member_id):
    """Only staff can delete members"""
    db = get_db()
    db.execute("DELETE FROM members WHERE id = ?", (member_id,))
    db.execute("DELETE FROM member_classes WHERE member_id = ?", (member_id,))
    db.commit()
    return redirect(url_for('view_members'))

# 🔹 Prevent Clickjacking & XSS Attacks
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'  # Prevent clickjacking
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME-type attacks
    response.headers["Content-Security-Policy"] = "default-src 'self';"
    return response

# 🔹 Secure Query Function (Prevents SQL Injection)
def query_db(query, args=(), one=False):
    """Execute queries safely using parameterized statements"""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

if __name__ == '__main__':
    app.run(debug=True)