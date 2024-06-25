import os
from flask import Flask, redirect, url_for, request, jsonify, session
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token, decode_token
from flask_httpauth import HTTPBasicAuth
from dotenv import load_dotenv
from bson.objectid import ObjectId
import uuid
import jwt
from pymongo import TEXT

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ardenarjuna28@gmail.com' #ganti pake email sendiri
app.config['MAIL_PASSWORD'] = 'qdwxvhgnfxokpzyk' 
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
app.config['MAIL_DEFAULT_SENDER'] = 'ardenarjuna28@gmail.com' #ganti pake email sendiri

print("MONGO_URI:", app.config['MONGO_URI'])  # Debugging output

mongo = PyMongo(app)
bcrypt = Bcrypt(app)
mail = Mail(app)
# jwt = JWTManag    er(app)
auth = HTTPBasicAuth()
login_manager = LoginManager(app)
login_manager.login_view = 'login'

google_bp = make_google_blueprint(client_id=os.getenv('GOOGLE_CLIENT_ID'), client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), redirect_to='google_login')
app.register_blueprint(google_bp, url_prefix='/login')

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.email = user_data['email']
        self.is_verified = user_data.get('is_verified', False)
        self.api_key = user_data.get('api_key')

    @staticmethod
    def create_user(username, email, password=None, google_id=None):
        user = {
            "username": username,
            "email": email,
            "password": bcrypt.generate_password_hash(password).decode('utf-8') if password else None,
            "google_id": google_id,
            "is_verified": False,
            "api_key": str(uuid.uuid4())
        }
        mongo.db.users.insert_one(user)
        return user

    @staticmethod
    def find_by_email(email):
        return mongo.db.users.find_one({"email": email})

    @staticmethod
    def find_by_google_id(google_id):
        return mongo.db.users.find_one({"google_id": google_id})

    @staticmethod
    def verify_password(stored_password, provided_password):
        return bcrypt.check_password_hash(stored_password, provided_password)

    @staticmethod
    def set_verified(user_id):
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'is_verified': True}})

@login_manager.user_loader
def load_user(user_id):
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
    return User(user) if user else None

@auth.verify_password
def verify_password(email, password):
    user_data = User.find_by_email(email)
    if user_data and User.verify_password(user_data['password'], password):
        return User(user_data)
    return None

def verify_api_key(api_key):
    user_data = mongo.db.users.find_one({"api_key": api_key})
    if user_data:
        return User(user_data)
    return None

def decodetoken(jwtToken):
    decode_result = decode_token(jwtToken)
    return decode_result

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({"message": "Missing username, email, or password"}), 400

    existing_user = User.find_by_email(email)
    if existing_user:
        if existing_user.get('is_verified', False):
            return jsonify({"message": "Email already registered"}), 400
        else:
            # Resend verification email
            # token = create_access_token(identity=existing_user['_id'], expires_delta=False)
            token= jwt.encode({
                        "username":username,
                        "user_email":email,
                },app.config['SECRET_KEY'],algorithm="HS256")
            msg = Message('Email Verification', recipients=[email])
            msg.body = f'Your verification link is: {token}'
            mail.send(msg)
            return jsonify({"message": "Verification email sent. Please check your inbox."}), 200

    user_data = User.create_user(username=username, email=email, password=password)

    # Send verification email
    token = create_access_token(identity=user_data['_id'], expires_delta=False)
    msg = Message('Email Verification', recipients=[email])
    msg.body = f'Your verification link is: {url_for("verify_email", token=token, _external=True)}'
    mail.send(msg)

    return jsonify({"message": "User registered successfully. Verification email sent."}), 201

mongo.db.users.create_index([("username", TEXT), ("email", TEXT)], default_language='english')

@app.route('/bearer-auth', methods=['GET'])
def detail_user():
    bearer_auth = request.headers.get('Authorization', None)
    if not bearer_auth:
        return {"message": "Authorization header missing"}, 401

    try:
        jwt_token = bearer_auth.split()[1]
        token = jwt.decode(jwt_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        username = token.get('username')
        user_email = token.get('user_email')

        if not username or not user_email:
            return {"message": "Token payload is invalid"}, 401

        user = mongo.db.users.find_one({"$or": [{"username": {"$regex": f'^{username}$', "$options": 'i'}},
                                                 {"email": {"$regex": f'^{user_email}$', "$options": 'i'}}]})
        if not user:
            return {"message": "User not found"}, 404

        # Update is_verified to True
        mongo.db.users.update_one({"_id": user["_id"]}, {"$set": {"is_verified": True}})

        data = {
            'username': user['username'],
            'email': user['email']
        }
    except Exception as e:
        return {
            'message': f'Token is invalid. Please log in again! {str(e)}'
        }, 401

    return jsonify(data), 200

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user_data = User.find_by_email(email)
    if user_data and User.verify_password(user_data['password'], password):
        if not user_data.get('is_verified'):
            return jsonify({"message": "Email not verified"}), 403
        user = User(user_data)
        login_user(user)
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

@app.route('/login/google')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))
    resp = google.get('/plus/v1/people/me')
    if not resp.ok:
        return jsonify({"message": "Google login failed"}), 400
    google_info = resp.json()
    google_id = google_info['id']
    email = google_info['emails'][0]['value']
    user_data = User.find_by_google_id(google_id)
    if not user_data:
        User.create_user(username=google_info['displayName'], email=email, google_id=google_id)
        user_data = User.find_by_google_id(google_id)
    user = User(user_data)
    login_user(user)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)

