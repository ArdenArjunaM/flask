import os
from flask import Flask, session, render_template, redirect, url_for, request, jsonify, send_file, Response, current_app, make_response
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
from flask import request, jsonify
from pymongo import TEXT

from flask_socketio import SocketIO, emit
import cv2
import numpy as np
import pandas as pd
import mediapipe as mp 
import pickle
import base64

from pymongo import TEXT, MongoClient

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

# import semua library yang dibutuhkan

@app.route('/api/verify_email', methods=['POST'])
def verify_email():
    data = request.json
    code = data.get('code')

    if not code:
        return jsonify({"message": "Kode verifikasi tidak disediakan"}), 400

    try:
        # Decode the token (assuming token is used as verification code)
        decoded_token = jwt.decode(code, app.config['SECRET_KEY'], algorithms=["HS256"])
        user_email = decoded_token.get('user_email')

        if not user_email:
            return jsonify({"message": "Token tidak valid"}), 400

        user = mongo.db.users.find_one({"email": user_email})

        if not user:
            return jsonify({"message": "Pengguna tidak ditemukan"}), 404

        # Set user as verified
        User.set_verified(user['_id'])

        return jsonify({"message": "Verifikasi berhasil"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token telah kedaluwarsa"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token tidak valid"}), 400
    except Exception as e:
        return jsonify({"message": f"Kesalahan terjadi: {str(e)}"}), 500

# sisa kode aplikasi Flask Anda


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

socketio = SocketIO(app)

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('message')
def handle_message(message):
    print('Received message:', message)


# Load Model
with open('assets\model_cobadataset.pkl', 'rb') as f:
    model = pickle.load(f)

# Mediapipe    
mp_holistic = mp.solutions.holistic
mp_drawing = mp.solutions.drawing_utils

@socketio.on('image')
def handle_image(image_data):
    try:
        body_language_prob = 0.0
        body_language_class = "none"
        image_data_bytes = base64.b64decode(image_data)
        image_array = np.frombuffer(image_data_bytes, dtype=np.uint8)
        decoded_image = cv2.imdecode(image_array, cv2.IMREAD_UNCHANGED)
        
        with mp_holistic.Holistic(min_detection_confidence=0.5, min_tracking_confidence=0.5) as holistic:
            image = cv2.cvtColor(decoded_image, cv2.COLOR_BGR2RGB)
            image = cv2.resize(image, (340, 180), interpolation=cv2.INTER_LINEAR)
            
            # Make Detections
            results = holistic.process(image)
            print('Detection results obtained')

            # Recolor image back to BGR for rendering
            image.flags.writeable = True
            image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
            
            mp_drawing.draw_landmarks(image, results.pose_landmarks, mp_holistic.POSE_CONNECTIONS,
                                      mp_drawing.DrawingSpec(color=(245,117,66), thickness=2, circle_radius=4),
                                      mp_drawing.DrawingSpec(color=(245,66,230), thickness=2, circle_radius=2))

            try:
                if results.pose_landmarks is not None:
                    # Extract Pose landmarks
                    pose = results.pose_landmarks.landmark
                    pose_row = list(np.array([[landmark.x, landmark.y, landmark.z, landmark.visibility] for landmark in pose]).flatten())
                    
                    # Concatenate rows
                    row = pose_row
                    
                    # Make Detections
                    X = pd.DataFrame([row])
                    body_language_class = model.predict(X)[0]
                    body_language_prob = model.predict_proba(X)[0]
                    
                    print(f'class: {body_language_class}, prob: {body_language_prob}')

                else:
                    print('No pose landmarks detected')
                
            except Exception as e:
                print('Error during prediction:', e)
    
        processed_image_bytes = cv2.imencode('.jpg', image)[1].tobytes()
        processed_image_data = base64.b64encode(processed_image_bytes).decode('utf-8')
        prob_float = float(np.max(body_language_prob))
        prob = str(prob_float)
        print(prob)

        emit('response', {"imageData": processed_image_data, "pose_class": body_language_class, "prob": prob})

    except Exception as e:
        print('Error processing image:', e)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["v2yoga"]
collection = db["deteksi"]

@app.route('/receivedata', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid data"}), 400

        tanggal = data.get("tanggal")
        pose_class = data.get("class")
        probability = data.get("probability")   

        if not all([tanggal, pose_class, probability]):
            return jsonify({"error": "Missing data fields"}), 400

        detection = {
            "tanggal": tanggal,
            "class": pose_class,
            "probability": probability
        }

        collection.insert_one(detection)
        return jsonify({"message": "Data successfully saved"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')

    # Check if email exists in MongoDB
    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'Email not found'}), 404

    # Generate a token (could use JWT or other methods)
    # Send reset password email with the token
    
    return jsonify({'message': 'Reset password email sent'}), 200

@app.route('/api/update_password', methods=['POST'])
def update_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')

    # Find user by email
    user = mongo.db.users.find_one({'email': email})
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Update password
    mongo.db.users.update_one(
        {'email': email},
        {'$set': {'password': bcrypt.generate_password_hash(new_password).decode('utf-8')}}
    )

    return jsonify({'message': 'Password updated successfully'}), 200


@app.route('/api/update_profile_picture', methods=['POST'])
def update_profile_picture():
    # Assuming you receive image data in base64 format
    data = request.json
    image_base64 = data.get('image_base64')

    # Process the image (save to storage or database)
    # Example: Save image to MongoDB GridFS or filesystem

    return jsonify({"message": "Profile picture updated successfully"}), 200

@app.route('/api/update_email', methods=['POST'])
def update_email():
    data = request.json
    new_email = data.get('new_email')

    # Update user's email in MongoDB
    # Example:
    # mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'email': new_email}})

    return jsonify({"message": "Email updated successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True)


