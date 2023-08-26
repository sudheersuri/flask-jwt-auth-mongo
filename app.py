from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from dotenv import load_dotenv
import os

app = Flask(__name__)
load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = os.getenv('MONGO_URI')
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    if mongo.db.users.find_one({'username': username}):
        return jsonify(message="Username already taken"), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    mongo.db.users.insert_one({'username': username, 'password': hashed_password})

    return jsonify(message="User registered successfully"), 201

# User login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    user = mongo.db.users.find_one({'username': username})

    if not user or not bcrypt.check_password_hash(user['password'], password):
        return jsonify(message="Invalid credentials"), 401

    access_token = create_access_token(identity=str(user['_id']))
    return jsonify(access_token=access_token), 200

# Protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    current_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    return jsonify(logged_in_as=current_user['username']), 200

if __name__ == '__main__':
    app.run(debug=True)
