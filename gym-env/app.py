from flask import Flask, render_template, request, redirect, url_for, session, g
from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from flask import Flask, send_file
import requests
import os
import pyotp
import qrcode
import sqlite3
import logging

# Configure logging
logging.basicConfig(
    filename='audit.log',  # Log file name
    level=logging.INFO,    # Logging level (e.g., INFO, DEBUG, WARNING)
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log format
)

app = Flask(__name__)
app.secret_key = "supersecretkey"  # To manage sessions (required by Flask)
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'


DATABASE = 'members.db'


# Simple user store for staff and members (no security library)
USERS = {
    "staff": {"password": "staffpass", "role": "staff", "otp_secret": "JBSWY3DPEHPK3PXP"},
    "member": {"password": "memberpass", "role": "member", "otp_secret": "JBSWY3DPEHPK3PXP"},
    "pakkarim": {"password": "karim", "role": "staff", "otp_secret": "JBSWY3DPEHPK3PXP"}
}



# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.before_request
def create_tables():
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



# FlaskForm for login with reCAPTCHA
class LoginForm(FlaskForm):
    username = StringField('Username')
    password = PasswordField('Password')
    recaptcha = RecaptchaField()
    submit = SubmitField('Login')
    
def verify_recaptcha(response):
    recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {'secret': app.config['RECAPTCHA_PRIVATE_KEY'], 'response': response}
    response = requests.post(recaptcha_url, data=payload)
    return response.json().get('success', False)


# Apply rate limiting to login route
@app.route('/', methods=['GET', 'POST'])

def login():
    form = LoginForm()
    if form.validate_on_submit():
        # reCAPTCHA validation first
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not verify_recaptcha(recaptcha_response):
            # If reCAPTCHA fails, prompt user with error message
            return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'], error="reCAPTCHA validation failed!")

        # Check if username exists and password is correct
        username = form.username.data
        password = form.password.data
        user = USERS.get(username)

        # If valid user and password, proceed to 2FA
        if user and user['password'] == password:
            session['user'] = username
            session['role'] = user['role']
            return redirect(url_for('two_factor'))

        # Show error if username or password is invalid
        return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'], error="Invalid username or password!")

    return render_template('login.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_PUBLIC_KEY'])


# Two-Factor Authentication (2FA) with QR Code
@app.route('/two_factor', methods=['GET', 'POST'])
def two_factor():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = USERS[session['user']]
    totp = pyotp.TOTP(user['otp_secret'])
    if request.method == 'GET':
        uri = totp.provisioning_uri(name=session['user'], issuer_name='MyCompany')
        qr_path = os.path.join('static', 'qr.png')
        if not os.path.exists('static'):
            os.makedirs('static')
        qrcode.make(uri).save(qr_path)
        return render_template('two_factor.html', qr_code_path=qr_path)

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            logging.info(f"2FA success for user: {session['user']}")
            return redirect(url_for('dashboard'))
        else:
            logging.warning(f"Invalid OTP entered by user: {session['user']}")
            return render_template('two_factor.html', error="Invalid OTP! Please try again.")

    # Handle POST request - Verify OTP entered by the user
    if request.method == 'POST':
        otp = request.form['otp']  # Get OTP entered by the user

        # Verify the OTP entered by the user
        if totp.verify(otp):
            return redirect(url_for('success'))  # Redirect to the success page if OTP is correct
        else:
            return "Invalid OTP! Please try again.", 400  # Return an error message if OTP is incorrect
        
# Generate a QR code for 2FA
totp = pyotp.TOTP('JCDCFY3DPEHPK3PXP')  # Secret key (replace with a unique key per user in production)
uri = totp.provisioning_uri(name='MyApp', issuer_name='Gym managment')

# Debug: Print URI to check it
print(f"Provisioning URI: {uri}")

# Create QR Code
qr = qrcode.make(uri)

# Ensure the static directory exists
static_dir = 'static'
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

# Debug: Print the static directory path
print(f"Saving QR code to: {os.path.join(static_dir, 'qr.png')}")

# Save QR code to the static folder
qr.save(os.path.join(static_dir, 'qr.png'))

print("QR code saved successfully!")

# Verify OTP Route
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form['otp']
        user = USERS[session['user']]
        totp = pyotp.TOTP(user['otp_secret'])

        if totp.verify(otp_input):
            return redirect(url_for('dashboard'))  # Successfully authenticated
        else:
            return "Invalid OTP!"

    return render_template('verify_otp.html')



@app.route('/success')
def success():
    # Ensure that user is logged in and 2FA was successful
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))  # Redirect to the dashboard


# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))  # If not logged in, redirect to login
    username = session['user']
    return render_template('dashboard.html', username=username)


@app.route('/add_member', methods=['GET', 'POST'])
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        logging.warning("Unauthorized access to add_member route.")
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        logging.info(f"Member added by {session['user']} - Name: {name}, Status: {status}")
        return redirect(url_for('view_members'))
    return render_template('add_member.html')


#veiw specific member class
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Get member classes
    member = query_db("SELECT * FROM members WHERE id = ?", [member_id], one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", [member_id])
    
    return render_template('member_classes.html', member=member, classes=classes)


#register class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))


    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)


#view users
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)


# New Route for Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')


# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')


@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)


#deleting member
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Delete member from the database
    db.execute("DELETE FROM members WHERE id = ?", [member_id])
    
    # Also delete any classes associated with the member in the member_classes table
    db.execute("DELETE FROM member_classes WHERE member_id = ?", [member_id])
    
    db.commit()
    
    return redirect(url_for('view_members'))


# Logout Route
@app.route('/logout')
def logout():
    user = session.pop('user', None)
    logging.info(f"User {user} logged out.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, port=5001)
