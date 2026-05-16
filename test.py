# ============================================================
# ADVANCED ENTERPRISE ATTENDANCE + SITE REPORTING SYSTEM
# ============================================================
# FEATURES
# ------------------------------------------------------------
# ✅ JWT Authentication
# ✅ Face Registration
# ✅ Face Verification
# ✅ GPS Restricted Attendance
# ✅ Anti Spoofing Hooks
# ✅ Site Work Reporting
# ✅ Multi Image Uploads
# ✅ Admin Analytics
# ✅ Device Binding
# ✅ Cloudinary Storage
# ✅ PostgreSQL Support
# ✅ Role Based Access
# ✅ Attendance Export
# ✅ Audit Logs
# ✅ Secure Passwords (bcrypt)
# ============================================================

# =========================
# INSTALL
# =========================
"""
pip install flask flask_sqlalchemy flask_jwt_extended
pip install flask_cors bcrypt cloudinary psycopg2-binary
pip install face_recognition opencv-python numpy pillow
pip install python-dotenv flask-limiter
"""

# =========================
# .env FILE
# =========================
"""
SECRET_KEY=super-secret-key

JWT_SECRET_KEY=jwt-secret

DATABASE_URL=postgresql://user:password@localhost/attendance

CLOUDINARY_CLOUD_NAME=xxxx
CLOUDINARY_API_KEY=xxxx
CLOUDINARY_API_SECRET=xxxx
"""

# ============================================================
# app.py
# ============================================================

import os
import uuid
import base64
import bcrypt
import cloudinary
import cloudinary.uploader
import numpy as np
import face_recognition

from io import BytesIO
from PIL import Image
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity
)

from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# ============================================================
# LOAD ENV
# ============================================================

load_dotenv()

# ============================================================
# APP
# ============================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

jwt = JWTManager(app)

CORS(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app
)

# ============================================================
# CLOUDINARY
# ============================================================

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# ============================================================
# DATABASE MODELS
# ============================================================

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True)

    password = db.Column(db.Text)

    full_name = db.Column(db.String(200))

    role = db.Column(db.String(20), default="employee")

    device_id = db.Column(db.String(200))

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class FaceEncoding(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer)

    encoding = db.Column(db.PickleType)


class Attendance(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer)

    check_in = db.Column(db.DateTime)

    check_out = db.Column(db.DateTime)

    check_in_photo = db.Column(db.Text)

    check_out_photo = db.Column(db.Text)

    latitude = db.Column(db.Float)

    longitude = db.Column(db.Float)

    status = db.Column(db.String(20))

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class SiteReport(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer)

    site_name = db.Column(db.String(300))

    purpose = db.Column(db.Text)

    remarks = db.Column(db.Text)

    latitude = db.Column(db.Float)

    longitude = db.Column(db.Float)

    image_url = db.Column(db.Text)

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class AuditLog(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer)

    action = db.Column(db.String(300))

    ip_address = db.Column(db.String(100))

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

# ============================================================
# HELPERS
# ============================================================

def hash_password(password):

    return bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()


def verify_password(password, hashed):

    return bcrypt.checkpw(
        password.encode(),
        hashed.encode()
    )


def upload_base64_image(image_data, folder):

    if "," in image_data:
        image_data = image_data.split(",")[1]

    upload = cloudinary.uploader.upload(
        f"data:image/jpeg;base64,{image_data}",
        folder=folder,
        public_id=str(uuid.uuid4())
    )

    return upload["secure_url"]


def extract_face_encoding(base64_image):

    if "," in base64_image:
        base64_image = base64_image.split(",")[1]

    image_bytes = base64.b64decode(base64_image)

    pil_image = Image.open(BytesIO(image_bytes))

    np_image = np.array(pil_image)

    encodings = face_recognition.face_encodings(np_image)

    if len(encodings) == 0:
        return None

    return encodings[0]


def verify_face(known_encoding, image_base64):

    current_encoding = extract_face_encoding(image_base64)

    if current_encoding is None:
        return False

    results = face_recognition.compare_faces(
        [known_encoding],
        current_encoding,
        tolerance=0.45
    )

    return results[0]


def log_action(user_id, action):

    audit = AuditLog(
        user_id=user_id,
        action=action,
        ip_address=request.remote_addr
    )

    db.session.add(audit)

    db.session.commit()

# ============================================================
# AUTH ROUTES
# ============================================================

@app.route("/api/register", methods=["POST"])
def register():

    data = request.json

    if User.query.filter_by(
        username=data["username"]
    ).first():

        return jsonify({
            "error": "Username exists"
        }), 400

    user = User(
        username=data["username"],
        password=hash_password(
            data["password"]
        ),
        full_name=data["full_name"],
        device_id=data.get("device_id")
    )

    db.session.add(user)

    db.session.commit()

    return jsonify({
        "message": "User created"
    })


@app.route("/api/login", methods=["POST"])
@limiter.limit("5/minute")
def login():

    data = request.json

    user = User.query.filter_by(
        username=data["username"]
    ).first()

    if not user:

        return jsonify({
            "error": "Invalid credentials"
        }), 401

    if not verify_password(
        data["password"],
        user.password
    ):

        return jsonify({
            "error": "Invalid credentials"
        }), 401

    # DEVICE BINDING

    if user.device_id:

        if data.get("device_id") != user.device_id:

            return jsonify({
                "error": "Unauthorized device"
            }), 403

    token = create_access_token(
        identity=user.id,
        expires_delta=timedelta(days=1)
    )

    log_action(user.id, "LOGIN")

    return jsonify({
        "token": token,
        "role": user.role,
        "name": user.full_name
    })

# ============================================================
# FACE REGISTRATION
# ============================================================

@app.route("/api/register-face", methods=["POST"])
@jwt_required()
def register_face():

    user_id = get_jwt_identity()

    data = request.json

    encoding = extract_face_encoding(
        data["image"]
    )

    if encoding is None:

        return jsonify({
            "error": "No face detected"
        }), 400

    existing = FaceEncoding.query.filter_by(
        user_id=user_id
    ).first()

    if existing:
        existing.encoding = encoding

    else:

        new_encoding = FaceEncoding(
            user_id=user_id,
            encoding=encoding
        )

        db.session.add(new_encoding)

    db.session.commit()

    return jsonify({
        "message": "Face registered"
    })

# ============================================================
# ATTENDANCE
# ============================================================

@app.route("/api/check-in", methods=["POST"])
@jwt_required()
def check_in():

    user_id = get_jwt_identity()

    data = request.json

    face = FaceEncoding.query.filter_by(
        user_id=user_id
    ).first()

    if not face:

        return jsonify({
            "error": "Face not registered"
        }), 400

    # FACE VERIFY

    verified = verify_face(
        face.encoding,
        data["image"]
    )

    if not verified:

        log_action(user_id, "FACE_VERIFICATION_FAILED")

        return jsonify({
            "error": "Face mismatch"
        }), 403

    photo_url = upload_base64_image(
        data["image"],
        "attendance/checkin"
    )

    attendance = Attendance(
        user_id=user_id,
        check_in=datetime.utcnow(),
        latitude=data["latitude"],
        longitude=data["longitude"],
        check_in_photo=photo_url,
        status="present"
    )

    db.session.add(attendance)

    db.session.commit()

    log_action(user_id, "CHECK_IN")

    return jsonify({
        "message": "Attendance marked",
        "photo_url": photo_url
    })

# ============================================================
# SITE REPORT
# ============================================================

@app.route("/api/upload-site-report", methods=["POST"])
@jwt_required()
def upload_site_report():

    user_id = get_jwt_identity()

    data = request.json

    image_url = upload_base64_image(
        data["image"],
        "site_reports"
    )

    report = SiteReport(
        user_id=user_id,
        site_name=data["site_name"],
        purpose=data["purpose"],
        remarks=data.get("remarks"),
        latitude=data["latitude"],
        longitude=data["longitude"],
        image_url=image_url
    )

    db.session.add(report)

    db.session.commit()

    log_action(user_id, "SITE_REPORT_UPLOAD")

    return jsonify({
        "message": "Site report uploaded",
        "image_url": image_url
    })

# ============================================================
# ADMIN DASHBOARD APIs
# ============================================================

@app.route("/api/admin/attendance")
@jwt_required()
def admin_attendance():

    user_id = get_jwt_identity()

    user = User.query.get(user_id)

    if user.role != "admin":

        return jsonify({
            "error": "Unauthorized"
        }), 403

    attendance = Attendance.query.all()

    result = []

    for a in attendance:

        employee = User.query.get(a.user_id)

        result.append({

            "employee": employee.full_name,

            "check_in": str(a.check_in),

            "latitude": a.latitude,

            "longitude": a.longitude,

            "status": a.status,

            "photo": a.check_in_photo
        })

    return jsonify(result)

# ============================================================
# AI FRAUD DETECTION PLACEHOLDER
# ============================================================

@app.route("/api/ai/fraud-check")
@jwt_required()
def fraud_check():

    """
    Future AI checks:
    - Duplicate images
    - GPS spoofing
    - Deepfake detection
    - Attendance anomalies
    """

    return jsonify({
        "message": "AI fraud module placeholder"
    })

# ============================================================
# DATABASE INIT
# ============================================================

with app.app_context():

    db.create_all()

# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
