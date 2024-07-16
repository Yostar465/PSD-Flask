import os
import threading
from flask import Flask, request, jsonify, Response, render_template, url_for, redirect
from ultralytics import YOLO
import cv2
from pytz import timezone
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
import datetime
import locale
from flask_cors import CORS
import yaml
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# ganti pake email sendiri
app.config['MAIL_USERNAME'] = 'muhammadabdillahnurziddan@gmail.com'
app.config['MAIL_PASSWORD'] = 'svcsdmwmuizqsdgm'
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
# ganti pake email sendiri
app.config['MAIL_DEFAULT_SENDER'] = 'muhammadabdillahnurziddan@gmail.com'

CORS(app)
mongo = PyMongo(app)
model = YOLO("models/best.pt")
locale.setlocale(locale.LC_TIME, 'id_ID.UTF-8')
bcrypt = Bcrypt(app)
mail = Mail(app)
jwt = JWTManager(app)
auth = HTTPBasicAuth()
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Baca file data.yaml
with open('data.yaml', 'r') as file:
    data = yaml.safe_load(file)

class_names = data['names']

# Durasi rekaman video dalam detik (1 menit)
video_duration = 60
# Interval waktu untuk mulai rekaman baru (5 menit)
recording_interval = 5 * 60


google_bp = make_google_blueprint(client_id=os.getenv(
    'GOOGLE_CLIENT_ID'), client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), redirect_to='google_login')
app.register_blueprint(google_bp, url_prefix='/login')

# Define the collection
parking_slots_collection = mongo.db.parking_slots


class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])  # Convert ObjectId to string
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
        result = mongo.db.users.insert_one(user)
        user['_id'] = str(result.inserted_id)  # Convert ObjectId to string
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
        mongo.db.users.update_one({'_id': ObjectId(user_id)}, {
                                  '$set': {'is_verified': True}})

    def update_password(self, new_password):
        hashed_password = bcrypt.generate_password_hash(
            new_password).decode('utf-8')
        mongo.db.users.update_one({'_id': ObjectId(self.id)}, {
                                  '$set': {'password': hashed_password}})


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


@app.route('/')
def record_video():
    cap = None
    out = None

    try:
        # Inisialisasi webcam (0 adalah indeks default untuk webcam utama)
        cap = cv2.VideoCapture(0)

        if not cap.isOpened():
            print("Error: Could not open webcam.")
            return

        # Ambil waktu sekarang sebagai nama file video
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        video_filename = f"parking_slot_{timestamp}.avi"

        # Codec dan inisialisasi VideoWriter
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        out = cv2.VideoWriter(video_filename, fourcc, 20.0,
                              (int(cap.get(3)), int(cap.get(4))))

        start_time = datetime.datetime.now()

        # Jumlah frame yang akan diabaikan di awal
        skip_initial_frames = 30
        frame_count = 0

        while (datetime.datetime.now() - start_time).seconds < video_duration:
            ret, frame = cap.read()
            if not ret:
                break

            # Abaikan beberapa frame awal
            if frame_count < skip_initial_frames:
                frame_count += 1
                continue

            # Deteksi objek di frame menggunakan model YOLOv8
            results = model(frame)

            # Inisialisasi counter slot parkir yang terisi
            free_slots = 0

            # Menggambar hasil deteksi pada frame
            for result in results:
                boxes = result.boxes
                for box in boxes:
                    # Koordinat bounding box
                    x1, y1, x2, y2 = map(int, box.xyxy[0])
                    confidence = box.conf[0]  # Tingkat kepercayaan deteksi
                    class_id = int(box.cls[0])  # ID kelas deteksi

                    # Tentukan warna bounding box berdasarkan label
                    if class_names[class_id] == 'belum terisi':
                        # Warna merah untuk slot yang terisi
                        color = (0, 0, 255)
                        free_slots += 1
                    else:
                        # Warna hijau untuk slot yang kosong
                        color = (0, 255, 0)

                    # Menggambar bounding box
                    cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)

                    # Menambahkan label dan confidence score
                    label = f'{class_names[class_id]}: {confidence:.2f}'
                    cv2.putText(frame, label, (x1, y1 - 10),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

            # Menampilkan jumlah slot terisi di pojok kiri atas
            count_text = f'Free Slots: {free_slots}'
            cv2.putText(frame, count_text, (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

            # Tulis frame ke video
            out.write(frame)

            frame_count += 1

        print(f"Video saved: {video_filename}")

        # Waktu saat ini dalam zona waktu WIB
        wib_time = datetime.datetime.now(datetime.timezone(
            'Asia/Jakarta')).strftime("%Y-%m-%d %H:%M:%S")

        # Simpan data ke MongoDB
        data_to_insert = {
            "Belum terisi": free_slots,
            "Waktu": wib_time
        }
        parking_slots_collection.insert_one(data_to_insert)
        print(f"Data inserted into MongoDB: {data_to_insert}")

    except Exception as e:
        print(f"Error during video recording: {e}")

    finally:
        if out:
            out.release()
        if cap:
            cap.release()

    # Set timer untuk rekaman berikutnya
    threading.Timer(recording_interval, record_video).start()


@app.route('/detect', methods=['GET'])
def detect():
    threading.Thread(target=record_video).start()
    return jsonify({"message": "Video recording and object detection started"}), 200


@app.route('/register', methods=['POST'])
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
            token = create_access_token(identity=str(
                existing_user['_id']), expires_delta=False)
            msg = Message('Email Verification', recipients=[email])
            msg.body = f'Your verification link is: {token}'
            mail.send(msg)
            return jsonify({"message": "Verification email sent. Please check your inbox."}), 200

    user_data = User.create_user(
        username=username, email=email, password=password)

    # Send verification email
    token = create_access_token(identity=user_data['_id'], expires_delta=False)
    msg = Message('Email Verification', recipients=[email])
    msg.body = f'Your verification link is: {token}'
    mail.send(msg)

    return jsonify({"message": "User registered successfully. Verification email sent."}), 201


@app.route('/auth', methods=['GET'])
def detail_user():
    bearer_auth = request.headers.get('Authorization', None)
    if not bearer_auth:
        return {"message": "Authorization header missing"}, 401

    try:
        jwt_token = bearer_auth.split()[1]
        token = decode_token(jwt_token)
        username = token.get('sub')

        if not username:
            return {"message": "Token payload is invalid"}, 401

        user = mongo.db.users.find_one({"_id": ObjectId(username)})
        if not user:
            return {"message": "User not found"}, 404

        # Update is_verified to True
        mongo.db.users.update_one({"_id": user["_id"]}, {
                                  "$set": {"is_verified": True}})

        data = {
            'username': user['username'],
            'email': user['email'],
            '_id': str(user['_id'])  # Convert ObjectId to string
        }
    except Exception as e:
        return {
            'message': f'Token is invalid. Please log in again! {str(e)}'
        }, 401

    return jsonify(data), 200


@app.route('/login', methods=['GET', 'POST'])
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


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    try:
        data = request.json
        current_password = data.get('Password lama')
        new_password = data.get('Password baru')

        if not current_password or not new_password:
            return jsonify({"message": "Missing current password or new password"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        if not User.verify_password(user_data['password'], current_password):
            return jsonify({"message": "Current password is incorrect"}), 401

        current_user.update_password(new_password)
        return jsonify({"message": "Password updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    try:
        data = request.form
        username = data.get('username')
        photo = request.files.get('photo')

        if not username:
            return jsonify({"message": "Missing username"}), 400

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        update_data = {'username': username}

        if photo:
            photo_filename = secure_filename(f"{current_user.id}.jpg")
            photo.save(os.path.join('static/uploads', photo_filename))
            update_data['photo'] = photo_filename

        mongo.db.users.update_one(
            {'_id': ObjectId(current_user.id)}, {'$set': update_data})

        return jsonify({"message": "Profile updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/change_email', methods=['POST'])
@login_required
def change_email():
    try:
        data = request.json
        new_email = data.get('new_email')

        if not new_email:
            return jsonify({"message": "Missing new email"}), 400

        existing_user = mongo.db.users.find_one({"email": new_email})
        if existing_user:
            return jsonify({"message": "Email is already in use"}), 409

        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        token = create_access_token(identity=str(
            current_user.id), expires_delta=False)
        msg = Message('Email Change Confirmation', recipients=[new_email])
        msg.body = f'Your email change confirmation token is: {token}'
        mail.send(msg)

        return jsonify({"message": "Email change confirmation sent. Please check your inbox."}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/confirm_change_email', methods=['POST'])
def confirm_change_email():
    bearer_auth = request.headers.get('Authorization', None)
    if not bearer_auth:
        return {"message": "Authorization header missing"}, 401

    try:
        jwt_token = bearer_auth.split()[1]
        token = decode_token(jwt_token)
        user_id = token.get('sub')

        if not user_id:
            return {"message": "Token payload is invalid"}, 401

        user = mongo.db.users.find_one({"_id": ObjectId(user_id)})
        if not user:
            return jsonify({"message": "User not found"}), 404

        data = request.json
        new_email = data.get('new_email')

        if not new_email:
            return jsonify({"message": "New email not provided"}), 400

        # Check if the new email is already used by another user
        existing_user = mongo.db.users.find_one({"email": new_email})
        if existing_user:
            return jsonify({"message": "Email is already in use"}), 409

        mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"email": new_email}}
        )
        return jsonify({"message": "Email changed successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/profile', methods=['GET'])
@login_required
def profile():
    try:
        user_data = mongo.db.users.find_one({"_id": ObjectId(current_user.id)})
        if not user_data:
            return jsonify({"message": "User not found"}), 404

        profile_data = {
            'username': user_data['username'],
            'email': user_data['email'],
            'photo': url_for('static', filename='uploads/' + user_data.get('photo', 'default_profile.jpg'))
        }

        return jsonify(profile_data), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.json
    email = data.get('email')
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not email or not old_password or not new_password:
        return jsonify({"message": "Email, old password, and new password are required"}), 400

    user_data = User.find_by_email(email)
    if not user_data:
        return jsonify({"message": "User not found"}), 404

    if not User.verify_password(user_data['password'], old_password):
        return jsonify({"message": "Old password is incorrect"}), 400

    hashed_password = bcrypt.generate_password_hash(
        new_password).decode('utf-8')
    mongo.db.users.update_one({'_id': user_data['_id']}, {
                              '$set': {'password': hashed_password}})
    return jsonify({"message": "Password changed successfully"}), 200


@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({"message": "Email is required"}), 400

    user_data = User.find_by_email(email)
    if not user_data:
        return jsonify({"message": "User not found"}), 404

    # Create a token for password reset (e.g., valid for 1 hour)
    token = create_access_token(identity=str(
        user_data['_id']), expires_delta=datetime.timedelta(hours=1))

    # Create a reset link
    reset_link = url_for('reset_password', token=token, _external=True)

    # Send email with reset link
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'Please click the link to reset your password: {reset_link}'
    mail.send(msg)

    return jsonify({"message": "Password reset link has been sent to your email"}), 200


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'GET':
        try:
            # Decode the token to ensure it's valid
            decode_token(token)
            return render_template('reset_password.html', token=token)
        except Exception as e:
            return jsonify({"message": f"Invalid or expired token: {str(e)}"}), 400

    if request.method == 'POST':
        try:
            # Decode the token
            decoded_token = decode_token(token)
            user_id = decoded_token['sub']

            # Find the user by ID
            user_data = mongo.db.users.find_one({"_id": ObjectId(user_id)})
            if not user_data:
                return jsonify({"message": "Invalid or expired token"}), 400

            # Get the new password from the request
            new_password = request.form.get('new_password')
            if not new_password:
                return jsonify({"message": "New password is required"}), 400

            # Hash the new password and update the user's password
            hashed_password = bcrypt.generate_password_hash(
                new_password).decode('utf-8')
            mongo.db.users.update_one({'_id': ObjectId(user_id)}, {
                                      '$set': {'password': hashed_password}})

            return jsonify({"message": "Password reset successfully"}), 200
        except Exception as e:
            return jsonify({"message": f"An error occurred: {str(e)}"}), 500


@app.route('/api/statistik', methods=['GET'])
def get_statistik():
    # Mengambil seluruh data tanpa _id
    data = list(parking_slots_collection.find({}, {"_id": 0}))
    return jsonify(data)


@app.route('/google_login')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get('/oauth2/v1/userinfo')
    user_info = resp.json()

    user = User.find_by_google_id(user_info['id'])
    if not user:
        user = User.create_user(
            username=user_info['name'], email=user_info['email'], google_id=user_info['id'])

    login_user(User(user))
    return jsonify({"message": "Login successful"}), 200


if __name__ == '__main__':
    app.run(debug=True, host='192.168.56.1', port=21079)
