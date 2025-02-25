from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import datetime
import os
import uuid  # For generating unique referral codes
from functools import wraps # For authentication decorator

app = Flask(_name_)

# Configuration (replace with your actual values)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your_secret_key' # Important!
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///linktree.db' # Use PostgreSQL in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1) # Adjust as needed
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = datetime.timedelta(days=30) # Adjust as needed

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    referral_code = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))  # UUID for referral codes
    referred_by = db.Column(db.Integer, db.ForeignKey('user.id')) # Self-referential for referrals
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    referrals = db.relationship('User', backref=db.backref('referrer', remote_side=[id]), lazy=True) # Relationship for referrals

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Referral(db.Model): # Optional, but good for tracking referral status
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    referred_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_referred = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status = db.Column(db.String(20), default='successful') # Could be 'pending', 'failed', etc.

# Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]  # Expecting "Bearer <token>"

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"]) # Important: Specify algorithm
            current_user = User.query.filter_by(id=data['user_id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message' : 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message' : 'Token is invalid!'}), 401
        except Exception as e: # Catch any other JWT errors
            return jsonify({'message' : 'Something went wrong with token'}), 401


        return f(current_user, *args, **kwargs) # Pass the user to the route function
    return decorated


# API Endpoints

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    referral_code = data.get('referral_code')

    # Validation (add more robust validation as needed)
    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400


    new_user = User()
    new_user.username = username
    new_user.email = email
    new_user.set_password(password) # Hash the password!

    if referral_code:
      referrer = User.query.filter_by(referral_code=referral_code).first()
      if referrer:
        new_user.referred_by = referrer.id # Link the referred user
        referral = Referral(referrer_id=referrer.id, referred_user_id=new_user.id) # Create a Referral record
        db.session.add(referral)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()  # Or email

    if user and user.check_password(password):
        # JWT token generation
        payload = {
            'user_id': user.id,  # Include user ID in the payload
            'exp': datetime.datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'], # Expiration time
            'iat': datetime.datetime.utcnow() # Issued at time
        }
        access_token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

        # Refresh token (optional but recommended)
        refresh_payload = {
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + app.config['JWT_REFRESH_TOKEN_EXPIRES'],
            'iat': datetime.datetime.utcnow()
        }
        refresh_token = jwt.encode(refresh_payload, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200 # Send both tokens

    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/refresh_token', methods=['POST']) # New route for refreshing tokens
def refresh():
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'message': 'Refresh token is missing'}), 401

    try:
        data = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        user = User.query.filter_by(id=data['user_id']).first()

        if user:
            access_payload = {
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES'],
                'iat': datetime.datetime.utcnow()
            }
            new_access_token = jwt.encode(access_payload, app.config['SECRET_KEY'], algorithm="HS256")
            return jsonify({'access_token': new_access_token}), 200

    except: # Catch token errors
        return jsonify({'message': 'Invalid or expired refresh token'}), 401


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    # ... (Implementation for password reset with email verification and token)
    return jsonify({'message': 'Password reset functionality not yet implemented'}), 501  # Placeholder


@app.route('/api/referrals', methods=['GET'])
@token_required # Protect this route
def get_referrals(current_user): # Access current_user here
    referrals = User.query.filter_by(referred_by=current_user.id).all()
    referral_list = [{'username': r.username, 'email': r.email} for r in referrals] # Customize as needed
    return jsonify(referral_list), 200

@app.route
