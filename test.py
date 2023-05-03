from flask import Flask, jsonify, request, redirect, url_for, send_from_directory, session, abort, make_response
import pexpect
import re
import os
import glob
from flask_cors import CORS
import redis
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token
import random
import urllib.parse
from urllib.parse import urlencode
from authlib.integrations.flask_client import OAuth
from flask import current_app
from models import User, db, CommandHistory, Credits
import secrets
from dotenv import load_dotenv
from authlib.integrations.base_client.errors import OAuthError
from urllib.parse import quote_plus
from flask_migrate import Migrate
from datetime import timedelta
from functools import wraps
from jwt import decode, exceptions
from better_profanity import profanity
import uuid
import shutil
from datetime import datetime
from werkzeug.utils import secure_filename
from traceback import format_exc
import stripe

load_dotenv()

app = Flask(__name__,static_url_path='',static_folder='static')
images_dir = '/home/mirror/invokeai/outputs/curator/'
CREDITS_PER_DOLLAR = 10

migrate = Migrate(app, db)

oauth = OAuth(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')

auth0_domain = os.environ["AUTH0_DOMAIN"]
auth0_client_id = os.environ["AUTH0_CLIENT_ID"]
auth0_client_secret = os.environ["AUTH0_CLIENT_SECRET"]
auth0_redirect_uri = os.environ.get('AUTH0_REDIRECT_URI')

app.config['STRIPE_SECRET_KEY'] = os.environ.get('STRIPE_SECRET_KEY')
app.config['STRIPE_WEBHOOK_SECRET'] = os.environ.get('STRIPE_WEBHOOK_SECRET')
stripe.api_key = app.config['STRIPE_SECRET_KEY']

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = './flask_session/'
app.secret_key = os.urandom(24)

CELERY_BROKER_URL = 'redis://localhost:6379/0'
Session(app)

oauth.register(
    "auth0",
    client_id=auth0_client_id,
    client_secret=auth0_client_secret,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{auth0_domain}/.well-known/openid-configuration'
)

db.init_app(app)
jwt = JWTManager(app)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.cookies.get('access_token')
        if not access_token:
            return redirect(url_for('login'))
        try:
            decode(access_token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        except exceptions.PyJWTError:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    server_metadata = oauth.auth0.load_server_metadata()

    # Get userinfo from the correct endpoint
    userinfo_endpoint = server_metadata["userinfo_endpoint"]
    resp = oauth.auth0.get(userinfo_endpoint)
    userinfo = resp.json()
    session["user"] = userinfo

    # Check if the user exists in your database
    user = User.query.filter_by(email=userinfo['email']).first()

    # If the user doesn't exist, create a new user
    if not user:
        user = User(
            auth0_user_id=userinfo["sub"],
            email=userinfo['email'],
            username=userinfo['nickname'],
            available_credits=15,
        )
        db.session.add(user)
        db.session.commit()
        print("New user created:", user)
    else:
        print("Existing user:", user)

    # Log in the user and provide a JWT token for user authorization
    access_token = create_access_token(identity=user.id, expires_delta=timedelta(hours=1))
    session['access_token'] = access_token
    
    # Set the access token as a cookie and redirect the user
    response = make_response(redirect("/"))
    response.set_cookie("access_token", access_token)
    return response

@app.route('/api/is-logged-in', methods=['GET'])
def is_logged_in():
    if 'user' in session:
        return jsonify(logged_in=True, user=session['user'])
    else:
        return jsonify(logged_in=False)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + auth0_domain
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": auth0_client_id,
            },
            quote_via=quote_plus,
        )
    )

# Create a Redis connection
r = redis.StrictRedis(host='localhost', port=6379, db=0)

# Update the progress value in Redis for a specific session
def set_progress(session_id, value):
    r.set(f"progress_{session_id}", value)

# Get the progress value from Redis for a specific session
def get_progress(session_id):
    return int(r.get(f"progress_{session_id}") or 0)

@app.route("/api/get-credits", methods=["GET"])
@jwt_required()
def get_available_credits():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if user:
        return jsonify({"available_credits": user.available_credits})
    else:
        return jsonify({"error": "User not found"}), 404

@app.route('/api/progress', methods=['GET'])
@jwt_required()
def api_get_progress():
    session_id = session.sid
    progress = get_progress(session_id)
    return {'progress': progress}

@app.route('/api/run-command', methods=['POST'])
@jwt_required()
def run_command():
    user_id = get_jwt_identity()
    command = request.form.get("command")
    sanitized_command = re.sub(r"(-[a-zA-Z]+)|[^a-zA-Z0-9\s\-.]", "", command)

    if contains_bad_words(sanitized_command):
        return "This command contains inappropriate content. Please refer to our content policy at https://mirrorize.ai/tos"

    # Get the user from the database
    try:
        user = User.query.filter_by(id=user_id).one()
    except NoResultFound:
        return jsonify({"error": "User not found"}), 404

    # Check if the user has enough credits
    cost = 1  # Cost of running the command
    if user.available_credits < cost:
        return "Error: Insufficient credits. Please buy more credits.", 403

    # Deduct the credits and update the database
    user.available_credits -= cost
    credit_deduction = Credits(user_id=user_id, amount=-cost, created_at=datetime.utcnow())
    db.session.add(credit_deduction)
    db.session.commit()

    output_filename, output_image_filepath = interact_with_program(sanitized_command)

    # Save the command and image URL to the database
    command_history = CommandHistory(user_id=user_id, command=sanitized_command, image_url=output_image_filepath, created_at=datetime.utcnow())
    db.session.add(command_history)
    db.session.commit()

    return output_filename

@app.route('/api/get-user-images', methods=['GET'])
@jwt_required()
def get_user_images():
    user_id = get_jwt_identity()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 9, type=int)

    images = CommandHistory.query.filter_by(user_id=user_id).paginate(page=page, per_page=per_page, error_out=False)
    
    images_data = [
        {
            "id": img.id,
            "command": img.command,
            "image_url": img.image_url,
            "created_at": img.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for img in images.items
    ]

    return jsonify({"images": images_data, "total_pages": images.pages})

@app.route('/api/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    user_id = get_jwt_identity()
    data = request.get_json()
    quantity = int(data.get('quantity'))

    try:
        # Set up the Stripe Checkout Session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'Mirrorize Credits ({quantity * 10})',
                    },
                    'unit_amount': 100,  # Price in cents (e.g., $0.40)
                },
                'quantity': quantity,
            }],
            mode='payment',
            success_url='https://mirrorize.ai/success',
            cancel_url='https://mirrorize.ai/cancel',
            client_reference_id=user_id,  # Add this line
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"id": checkout_session.id})

@app.route('/api/webhook', methods=['POST'])
def handle_checkout_session_completed():
    payload = request.get_data(as_text=True)
    signature_header = request.headers.get('stripe-signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, signature_header, app.config['STRIPE_WEBHOOK_SECRET']
        )
    except ValueError:
        print("Invalid payload:", payload)
        return "Invalid payload", 400
    except stripe.error.SignatureVerificationError:
        print("Invalid signature:", signature_header)
        return "Invalid signature", 400

    if event.type == 'checkout.session.completed':
        session = event.data.object
        user_id = session.get('client_reference_id')
        if user_id:
            amount_paid = session.get('amount_total', 0) // 100
            credits_to_add = amount_paid * CREDITS_PER_DOLLAR

            user = User.query.get(user_id)
            if user:
                user.available_credits += credits_to_add
                credit_addition = Credits(user_id=user_id, amount=credits_to_add, created_at=datetime.utcnow())
                db.session.add(credit_addition)
                db.session.commit()

                print(f"Added {credits_to_add} credits to user {user_id}")
            else:
                print(f"User not found: {user_id}")

    return jsonify({"status": "success"})

@app.route('/api/delete-image/<int:image_id>', methods=['DELETE'])
@jwt_required()
def delete_image(image_id):
    user_id = get_jwt_identity()  # Implement this function to get the user_id from the access token
    if not user_id:
        return jsonify({"error": "Invalid user"}), 401

    image = CommandHistory.query.filter_by(id=image_id, user_id=user_id).first()
    if not image:
        return jsonify({"error": "Image not found"}), 404

    try:
        os.remove(os.path.join('/home/mirror/invokeai/outputs', secure_filename(image.image_url)))
    except FileNotFoundError:
        pass  # If the image file is not found, we will still proceed to delete the image record from the database.

    db.session.delete(image)
    db.session.commit()

    return jsonify({"message": "Image successfully deleted"})

@app.route('/api/output-image/<filename>', methods=['GET'])
@jwt_required()
def output_image(filename):
    return send_from_directory('/home/mirror/invokeai/outputs', filename)

@app.route('/api/random-prompt', methods=['GET'])
def pullrandom():
    rprompt = prompts('pr2.txt','10', '2')
    return {'text': rprompt}

@app.route('/api/list-images')
def list_images():
    files = os.listdir(images_dir)
    image_files = [f for f in files if f.lower().endswith(('.jpg', '.png'))]
    return jsonify(image_files)

@app.route('/api/images/<path:filename>')
def serve_image(filename):
    return send_from_directory(images_dir, filename)

@app.route('/outputs/<path:image_path>')
def swerve_image(image_path):
    return send_from_directory('/home/mirror/invokeai/outputs', image_path)

@app.route('/app')
@login_required
def about():
    return send_from_directory('static', 'app.html')

@app.route('/dash')
@login_required
def dash():
    return send_from_directory('static', 'dash.html')

@app.route('/music')
def music():
    return send_from_directory('static', 'music.html')

@app.route('/explore')
def explore():
    return send_from_directory('static', 'explore.html')

@app.route('/privacy')
def privacy():
    return send_from_directory('static', 'privacy.html')

@app.route('/tos')
def tos():
    return send_from_directory('static', 'tos.html')

@app.route('/')
def home():
    return send_from_directory('static', 'index.html')

@app.route('/support')
def support():
    return send_from_directory('static', 'support.html')

@app.route('/cancel')
def cancel():
    return send_from_directory('static', 'cancel.html')

@app.route('/success')
def success():
    return send_from_directory('static', 'success.html')

def contains_bad_words(text):
    # Returns True if the text is profane, False otherwise
    return profanity.contains_profanity(text)

def log_command(user_id, command, image_url=None):
    command_history = CommandHistory(
        user_id=user_id,
        command=command,
        image_url=image_url,
        created_at=datetime.utcnow()
    )

    db.session.add(command_history)
    db.session.commit()

def prompts(prompts, num_word, artists):
	if prompts == "pr1.txt":
		prompt = open('pr1.txt', encoding='utf-8').read().splitlines()
	elif prompts == "pr2.txt":
		prompt = open('pr2.txt', encoding='utf-8').read().splitlines()

	if num_word == None:
		num_word = 10
	if artists == None:
		artists = 2

	generated = []
	artists_num = 0
	
	while len(sorted(set(generated), key=lambda d: generated.index(d))) < int(num_word):
		rand = random.choice(prompt)
		if rand.startswith('art by') and int(artists_num) < int(artists):
			artists_num +=1 
			generated.append(rand)
		elif not rand.startswith('art by'):
			generated.append(rand)

	return ', '.join(set(generated))

def interact_with_program(sanitized_command):
    session_id = session.sid
    output_image_folder = '/home/mirror/invokeai/outputs/'
    set_progress(session_id, 0)
    
    try:
        child = pexpect.spawn("/home/mirror/invokeai/invoke.sh")

        child.sendline("2")
        child.expect(r".*\((.*?)\) invoke>", timeout=30)

        child.sendline(sanitized_command)

        while True:
            i = child.expect([r"(\d+)%\|", r".*\((.*?)\) invoke>"], timeout=30)
            if i == 0:
                set_progress(session_id, int(child.match.group(1)))
            elif i == 1:
                break

        set_progress(session_id, 0)

        output_files = glob.glob('/home/mirror/invokeai/outputs/*.png')
        output_files.sort(key=os.path.getctime, reverse=True)

        if output_files:
            output_filename = output_files[0]
            relative_filepath = output_filename.replace('/home/mirror/invokeai/outputs/', '')

            # Save the output image filename
            output_image_filename = f"{uuid.uuid4()}.png"
            shutil.copyfile(output_filename, os.path.join(output_image_folder, output_image_filename))

            # Move the original file to /media/usb/drive
            destination_directory = "/media/mirror/One Touch/mirrorimg"
            destination_file_path = os.path.join(destination_directory, os.path.basename(output_filename))
            shutil.move(output_filename, destination_file_path)

            return output_image_filename, output_image_filename

        return f"Error: Could not find output filename in the output directory", None
    except Exception as e:
        set_progress(session_id, 0)
        return f"Error: {str(e)}", None

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=8000, debug=False)
