from flask import Flask, render_template, request, redirect, url_for, flash, g, session, send_from_directory, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_login import current_user
import stripe
from dotenv import load_dotenv
import mysql.connector
import psycopg2
import os
import json
from itsdangerous import URLSafeTimedSerializer
from emails import send_mail_pw_reset, send_welcome_email, send_mail_verification
from functools import wraps
from flask_dance.contrib.google import make_google_blueprint, google
from utils import predict_approval
import config # this line is problematic because build_features.py reads it line 1
import sys
sys.path.append('../pipelines/')
from etl.config import COURSE_NAMES
from models.config import FEATURES

from database_models import db, UserUsage, User


app = Flask(__name__)

# Set a secret key for the application
app.secret_key = os.environ["FLASK_SECRET_KEY"]

load_dotenv()

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT')
app.config['PREFERRED_URL_SCHEME'] = 'https'

google_bp = make_google_blueprint(
    client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

login_manager = LoginManager()
login_manager.init_app(app)

db_password = os.environ.get('POSTGRES_PASSWORD')

CORS(app)

# MySQL configuration
#DATABASE_URL = f"mysql -roundhouse.proxy.rlwy.net -uroot -p{db_password} --port 35112 --protocol=TCP railway"
DATABASE_URL = f"postgres://rnudzlcskumoue:{db_password}@ec2-54-167-29-148.compute-1.amazonaws.com:5432/d9a73e9glockc"
SQLALCHEMY_DATABASE_URI = f"postgresql://rnudzlcskumoue:{db_password}@ec2-54-167-29-148.compute-1.amazonaws.com:5432/d9a73e9glockc"
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
db.init_app(app)

DATABASE_CONFIG = {
            'user': 'rnudzlcskumoue',
            'password': os.environ.get('POSTGRES_PASSWORD'),
            'host': 'ec2-54-167-29-148.compute-1.amazonaws.com',
            'port': '5432',
            'database': 'd9a73e9glockc'
        }

# def get_db():
#     if hasattr(g, 'db_conn') and g.db_conn.is_connected():
#         return g.db_conn
#     else:
#         g.db_conn = mysql.connector.connect(**DATABASE_CONFIG)
#         return g.db_conn


stripe_keys = {
    "secret_key": os.environ["STRIPE_SECRET_KEY"],
    "publishable_key": os.environ["STRIPE_PUBLISHABLE_KEY"],
    "endpoint_secret": os.environ["STRIPE_ENDPOINT_SECRET"], # new
}

stripe.api_key = stripe_keys["secret_key"]

with open("data/ui/approved_stats_2020_2022.json", "r") as file:
    approved_stats = json.load(file)

def get_db():
    if hasattr(g, 'db_conn') and g.db_conn.closed == 0:
        return g.db_conn
    else:
        g.db_conn = psycopg2.connect(**DATABASE_CONFIG)
        return g.db_conn

@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, 'db_conn', None)
    if db is not None:
        db.close()

@login_manager.unauthorized_handler
def unauthorized():
    # Redirect unauthorized users to the index page
    flash("You must be logged in to access this page.", "warning")
    return redirect(url_for('login', next=request.url))

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cursor = conn.cursor()

    # Query to find user by the auto-incremented id
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    cursor.close()

    if user:
        user_obj = UserMixin()
        user_obj.id = user[0]  # The auto-incremented ID
        user_obj.username = user[1]
        user_obj.email = user[2]
        user_obj.password = user[3]
        user_obj.role_id = user[4]
        user_obj.email_confirmed = user[5]
        user_obj.payment = user[6]
        return user_obj

    return None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = generate_password_hash(request.form.get('password'))

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email=%s OR username=%s', (email, username))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email or username already exists. Choose another one.')
            return redirect(url_for('signup'))

        # welcome credits logic, add 2 credits instead of O
        cursor.execute('INSERT INTO users (username, email, password, role_id, payment) VALUES (%s, %s, %s, %s, %s)',
                       (username, email, password, 2, False))

        conn.commit()
        conn.close()

        # Send email verification
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = s.dumps(email, salt='email-confirm')
        verification_url = url_for("confirm_email", token=token, _external=True)

        send_mail_verification(email, verification_url)

        session['email'] = email

        return redirect(url_for('check_email'))

    return render_template('signup.html')

@app.route('/check-email')
def check_email():
    email = session.get('email', None)
    if not email:
        return redirect(url_for('signup'))  # Or handle this case as you see fit
    return render_template('check_email.html', email=email)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cursor.fetchone()
        conn.close()

        # Check if user exists and password is correct
        if user and check_password_hash(user[3], password):

            # Check if the email is confirmed, assuming email_confirmed is the 7th column (index 6)
            if not user[5]:  # Adjust the index if necessary
                flash('Please verify your email before logging in. Check your inbox.')
                #return redirect(url_for('login'))

            user_obj = UserMixin()
            user_obj.id = user[0]
            login_user(user_obj)
            next_page = request.form.get('next')

            session['email'] = email

            print(f"email: {email}")
            print(f"Next Page: {next_page}")

            return redirect(next_page or url_for('app_page'))

        else:
            flash('Invalid email or password.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()

    session.pop('username', None)

    return redirect(url_for('index'))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('app_page'))
    return render_template('index.html')


@app.route("/config")
def get_publishable_key():
    """
    Now, after the page load, a call will be made to /config, which will
    respond with the Stripe publishable key. We'll then use this key to 
    create a new instance of Stripe.js.
    """
    stripe_config = {"publicKey": stripe_keys["publishable_key"]}
    return jsonify(stripe_config)


@app.route("/create-checkout-session")
def create_checkout_session():

    domain_url = os.environ.get("DOMAIN_URL", "http://127.0.0.1:5000/")
    stripe.api_key = stripe_keys["secret_key"]

    try:
        # Create new Checkout Session for the order
        # Other optional params include:
        # [billing_address_collection] - to display billing address details on the page
        # [customer] - if you have an existing Stripe Customer ID
        # [payment_intent_data] - capture the payment later
        # [customer_email] - prefill the email input in the form
        # For full details see https://stripe.com/docs/api/checkout/sessions/create

        # ?session_id={CHECKOUT_SESSION_ID} means the redirect will have the session ID set as a query param
        checkout_session = stripe.checkout.Session.create(
            #client_reference_id=current_user.id if current_user.is_authenticated else None,
            success_url=domain_url + "success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "cancelled",
            payment_method_types=["card"],
            mode="payment",
            line_items=[
                {
                    "price": "price_1OTwBXD1X8yObih9MXQpufKP",
                    #"name": "T-shirt",
                    "quantity": 1,
                    #"currency": "usd",
                    #"amount": "2000",
                    
                }
            ]
        )
        return jsonify({"sessionId": checkout_session["id"]})
    except Exception as e:
        return jsonify(error=str(e)), 403


@app.route("/success")
def success():

    if 'email' in session:
        user_id = session['email']
        #feature_name = 'your_feature_name'

        # Update usage count in the database
        user = User.query.filter_by(email=user_id).first()
        if user is not None:
            user.payment = True
           
        else:
            raise ValueError("User is None")

    print(f"user.payment: {user.payment}")

    db.session.commit()

    return render_template("success.html")


@app.route("/cancelled")
def cancelled():
    return render_template("cancelled.html")

@app.route("/webhook", methods=["POST"])
def stripe_webhook():
    """
    Do not read s3 files here!
    """
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get("Stripe-Signature")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_keys["endpoint_secret"]
        )

    except ValueError as e:
        # Invalid payload
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return "Invalid signature", 400

    # Handle the checkout.session.completed event
    print(f"event['type']: {event['type']}")
    if event["type"] == "checkout.session.completed":
        print("Payment was successful.")
        
        # TODO: run some custom code here
        # event_id = event["id"]
        # checkout_session_id = event["data"]["object"]["id"]
        # email = event["data"]["object"]["customer_details"]["email"]
        # print(f"email: {email}")
        
        # try:
        #     # Existing code...
        #     print("Inside of try!")
        #     response = s3.get_object(Bucket=BUCKET_NAME, Key=USER_LINKS_FILE)
        #     print(f"response:\n{response}")
        #     user_links = json.loads(response['Body'].read().decode('utf-8'))
        #     print(f"user_links inside webhook:\n{user_links}")
        #     print("Final of try!")

        # except s3.exceptions.NoSuchKey as e:
        #     # Handle the case when the S3 object does not exist
        #     print(f"S3 object not found: {e}")
        # except Exception as e:
        #     # Handle other exceptions
        #     print(f"An error occurred: {e}")
        #         # Store the link in the database
        #response = s3.get_object(Bucket=BUCKET_NAME, Key=USER_LINKS_FILE)
        #object_body = response['Body'].read().decode('utf-8')
        #print(f" object_body:\n{ object_body}")
        #user_links = json.loads(response['Body'].read().decode('utf-8'))
        # user_links[email] = {
        #     "event_id": event_id,
        #     "checkout_session_id": checkout_session_id,
        #     "user_identifier": str(uuid.uuid4()),
        #     "click_counter": 0,
        # }
        
        # Store the link in the JSON file
        #save_user_links_to_file(user_links)

    return "Success", 200


def generate_reset_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def verify_reset_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return False
    return email

@app.route('/request-reset', methods=['GET', 'POST'])
def request_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user:
            token = generate_reset_token(email)
            reset_url = url_for('reset_with_token', token=token, _external=True)

            # Use your SendInBlue function to send email with reset_url.
            send_mail_pw_reset(email,reset_url)

            flash('Password reset link has been sent to your email', 'success')
        else:
            flash('This email is not registered', 'error')
    return render_template('request_reset.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()

    # Check if the user exists in the database using their email
    cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
    user = cursor.fetchone()

    if user:
        # Check if email is already confirmed
        if user[5]:
            flash('Email already confirmed. Please log in.', 'info')
            conn.close()
            return redirect(url_for('login'))

        # Update the user's email confirmation status in the database
        cursor.execute('UPDATE users SET email_confirmed = TRUE, email_confirmed_on = NOW() WHERE email = %s', (email,))
        conn.commit()

        # Send welcome email after successful email confirmation
        send_welcome_email(email)
        print("Welcome Email sent")


        flash('Thank you for confirming your email! Please log in.', 'success')

        session['email_confirmed'] = True

    else:
        flash('Error! User not found.', 'danger')

    conn.close()

    return redirect(url_for('login'))

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check if the user exists and hasn't confirmed their email
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Generate a verification token and send the email
            s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token = s.dumps(email, salt='email-confirm')
            verification_url = url_for("confirm_email", token=token, _external=True)
            send_mail_verification(email, verification_url)

            flash('Verification email has been resent. Please check your inbox.', 'success')
        else:
            flash('This email address is not registered or has already been verified.', 'danger')

        return redirect(url_for('login'))

    return render_template('resend_verification.html')


@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404



@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired token', 'error')
        return redirect(url_for('request_reset'))

    if request.method == 'POST':
        new_password = generate_password_hash(request.form.get('password'))

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('UPDATE users SET password = %s WHERE email = %s', (new_password, email))
        conn.commit()

        flash('Password has been updated', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


@app.route('/app')
@login_required
def app_page():
    
    return render_template('app.html')


# This route handles the form submission and then redirects to /result
@app.route('/submit')
def submit_form():
    # Your processing logic for the form data goes here
    # For example, you can retrieve form data using request.form.get('<input_name>')
    data = {
        'escore_bruto_p1_etapa1': float(request.args.get('escore_bruto_p1_etapa1')),
        'escore_bruto_p2_etapa1': float(request.args.get('escore_bruto_p2_etapa1')),
        'escore_bruto_p1_etapa2': float(request.args.get('escore_bruto_p1_etapa2')),
        'escore_bruto_p2_etapa2': float(request.args.get('escore_bruto_p2_etapa2')),
        'escore_bruto_p1_etapa3': float(request.args.get('escore_bruto_p1_etapa3')),
        'escore_bruto_p2_etapa3': float(request.args.get('escore_bruto_p2_etapa3')),
        'cotas_negros_flag': int(request.args.get('cotas_negros_flag')),
        'publicas1_flag': int(request.args.get('publicas1_flag')),
        'publicas2_flag': int(request.args.get('publicas2_flag')),
        'publicas3_flag': int(request.args.get('publicas3_flag')),
        'publicas4_flag': int(request.args.get('publicas4_flag')),
        'publicas5_flag': int(request.args.get('publicas5_flag')),
        'publicas6_flag': int(request.args.get('publicas6_flag')),
        'publicas7_flag': int(request.args.get('publicas7_flag')),
        'publicas8_flag': int(request.args.get('publicas8_flag')),
        'course': request.args.get('course'),
    }

    course = request.args.get('course')
    course_stats = approved_stats[course]
    approval_prediction = predict_approval(data)

    # Store the data in the session
    session['course'] = course
    session['course_stats'] = course_stats
    session['approval_prediction'] = approval_prediction

    # Apply incrementing here
    #counterDisplay = session["counterDisplay"] + 1
    #user_identifier = session['data']
    
    # Check if user is logged in
    #if 'user_id' in session:
    if 'email' in session:
        user_id = session['email']
        feature_name = 'your_feature_name'

        # Update usage count in the database
        user_usage = UserUsage.query.filter_by(user_id=user_id, feature_name=feature_name).first()
        if user_usage is None:
            user_usage = UserUsage(user_id=user_id, feature_name=feature_name, usage_count=1)
        else:
            user_usage.usage_count += 1

    print(f"user_usage: {user_usage}")

    db.session.add(user_usage)
    db.session.commit()

    usage_threshold = 5  # Set your desired threshold
    user = User.query.filter_by(email=user_id).first()
    print(f"user.payment: {user.payment}")

    if user.payment is not True:
        # Check if usage count exceeds the threshold
        if user_usage.usage_count > usage_threshold:
            return redirect(url_for('payment_page'))
    
    #response = s3.get_object(Bucket=BUCKET_NAME, Key=USER_LINKS_FILE)
    #user_links = json.loads(response['Body'].read().decode('utf-8'))
    #email, user_content = get_user_dict(user_links, user_identifier)
    #user_links[email]['click_counter'] = counterDisplay

    # Store the link in the JSON file
    #save_user_links_to_file(user_links)

    # After processing, redirect to /result without exposing query parameters
    return redirect(url_for('result'))


@app.route('/payment')
def payment_page():
    # Your payment page logic here...
    return render_template("paymentpage.html")


@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if resp.ok:
        google_info = resp.json()
        google_user_id = str(google_info["id"])

        # Establish a database connection
        conn = get_db()
        cursor = conn.cursor()

        # Check if the user exists in your database by their Google ID
        cursor.execute('SELECT * FROM users WHERE google_id = %s', (google_user_id,))
        user = cursor.fetchone()

        if not user:
            # User does not exist, create a new user with Google info
            username = google_info.get("name")
            email = google_info.get("email")

            # Insert new user into your database
            cursor.execute('INSERT INTO users (username, email, google_id, role_id) VALUES (%s, %s, %s, %s)',
                           (username, email, google_user_id,2))
            conn.commit()
            user_id = cursor.lastrowid  # Get the auto-incremented ID of the new user
        else:
            # User exists, get their auto-incremented ID
            user_id = user[0]

        conn.close()

        # Load the user and log them in using Flask-Login
        user_obj = load_user(user_id)
        if user_obj:
            login_user(user_obj)

        return redirect(url_for('app_page'))  # Redirect to the application's main page
    else:
        return "Failed to fetch user info from Google.", 403

@app.route('/logout/google')
def google_logout():
    token = blueprint.token["access_token"]
    resp = google.post(
        "https://accounts.google.com/o/oauth2/revoke",
        params={"token": token},
        headers={"content-type": "application/x-www-form-urlencoded"}
    )
    assert resp.ok, resp.text
    logout_user()  # Flask-Login's logout
    return redirect(url_for('index'))

@app.route('/clear-session')
def clear_session():
    session.clear()
    return 'Session cleared!'

@app.route("/confirmation")
@login_required
def confirmation_page():
#def confirmation_page(event_id, email):
    
    #response = s3.get_object(Bucket=BUCKET_NAME, Key=USER_LINKS_FILE)
    #user_links = json.loads(response['Body'].read().decode('utf-8'))
    
    # user_identifier comes from parameter function
    #print(f"user_identifier: {user_identifier}")
    #print(f"user_links: {user_links}")
        
    # Ensure the user_id is valid (you might want to add more checks)
    #user_identifiers = [user_links[key]["user_identifier"] for key in user_links]
    #if user_identifier not in user_identifiers:
    #    return "Invalid user ID or payment not registered", 404

    data = {
        'features': FEATURES,
        'course_names' : COURSE_NAMES
    }

    # Store the data in the session
    #user_identifier = 999
    #session['data'] = user_identifier

    #_, user_content = get_user_dict(user_links, user_identifier)
    #counterDisplay = user_content['click_counter']
    #counterDisplay = 4
    # Store the data in the session
    #session['counterDisplay'] = counterDisplay
        
    #if counterDisplay > 5:
    #    return render_template("click_count_warning.html")

    if 'email' in session:
        user_id = session['email']
        feature_name = 'your_feature_name'

        # Update usage count in the database
        user_usage = UserUsage.query.filter_by(user_id=user_id, feature_name=feature_name).first()
        try:
            counterDisplay = user_usage.usage_count
        except AttributeError:
            counterDisplay = 0

    # Perform any additional actions or render a confirmation page
    # In this example, we'll just render a simple template
    #return render_template("confirmation_page.html", email=email, event_id=event_id, unique_link=unique_link)
    return render_template(
        "formpage.html",
    #    email=user_identifier,
        data=data,
        counterDisplay=counterDisplay
    )


@app.route('/result')
def result():
    # data = {
    #     'escore_bruto_p1_etapa1': float(request.args.get('escore_bruto_p1_etapa1')),
    #     'escore_bruto_p2_etapa1': float(request.args.get('escore_bruto_p2_etapa1')),
    #     'escore_bruto_p1_etapa2': float(request.args.get('escore_bruto_p1_etapa2')),
    #     'escore_bruto_p2_etapa2': float(request.args.get('escore_bruto_p2_etapa2')),
    #     'escore_bruto_p1_etapa3': float(request.args.get('escore_bruto_p1_etapa3')),
    #     'escore_bruto_p2_etapa3': float(request.args.get('escore_bruto_p2_etapa3')),
    #     'cotas_negros_flag': int(request.args.get('cotas_negros_flag')),
    #     'publicas1_flag': int(request.args.get('publicas1_flag')),
    #     'publicas2_flag': int(request.args.get('publicas2_flag')),
    #     'publicas3_flag': int(request.args.get('publicas3_flag')),
    #     'publicas4_flag': int(request.args.get('publicas4_flag')),
    #     'publicas5_flag': int(request.args.get('publicas5_flag')),
    #     'publicas6_flag': int(request.args.get('publicas6_flag')),
    #     'publicas7_flag': int(request.args.get('publicas7_flag')),
    #     'publicas8_flag': int(request.args.get('publicas8_flag')),
    #     'course': request.args.get('course'),
    # }

    # approval_prediction = predict_approval(data)

    result_data = {
        'approval_prediction': session['approval_prediction']
    }
    
    # Access the data from the session
    received_data = session.get('data', {})

    print(f"received_data: {received_data}")

    course = session['course']

    original_course_stats = session['course_stats']

    course_stats = {}

    for key, value in original_course_stats.items():
        parts = key.split('_')
        try:
            new_key = f"Escore Bruto Parte {parts[2][-1]} Etapa {parts[3][-1]}"
        except IndexError:
            new_key = 'Argumento Final'
        course_stats[new_key] = value
    
    return render_template('resultpage.html', data=result_data, received_data=received_data, course_stats=course_stats, course=course)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(
        #ssl_context=('cert.pem', 'key.pem'),
        debug=True,
        host='0.0.0.0',
        port=port
    )