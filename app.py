from flask import Flask, request, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import datetime
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec  # Import for EC keys

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_fallback_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="http://localhost:3000")

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

with app.app_context():
    db.create_all()

connected_users = {}
user_keys = {} # Store shared secrets per user (now derived from ECDH)

# --- Encryption Utilities (Remains the same for message encryption) ---
def derive_key(password, salt, iterations=100000, key_length=32):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv.bytes + ciphertext).decode('utf-8')

def decrypt_message(key, ciphertext_base64):
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_base64)
        iv = ciphertext_bytes[:16]
        ciphertext = ciphertext_bytes[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize().decode('utf-8')
        return plaintext
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return "Decryption Error"

# --- Web Crypto API Key Exchange ---
server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
server_public_key = server_private_key.public_key()
server_public_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
server_public_pem = server_public_bytes.decode('utf-8')

@socketio.on('connect')
def handle_connect():
    print('Client connected:', request.sid)
    socketio.emit('dh_params', {'server_public_key': server_public_pem}, room=request.sid)

@socketio.on('client_public_key')
def handle_client_public_key(data):
    username = data.get('username')
    client_public_key_pem = data.get('public_key')
    if username and client_public_key_pem:
        print(f"Received client public key from {username}: {client_public_key_pem[:50]}...")
        try:
            client_public_bytes = base64.b64decode(client_public_key_pem.encode('utf-8'))
            client_public_key = serialization.load_pem_public_key(
                client_public_bytes, backend=default_backend()
            )
            print(f"Loaded public key for {username} successfully.")
            shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
            shared_key = shared_secret.hex()
            print(f"Shared secret for {username}: {shared_key[:20]}...")
            user_keys[username] = shared_key # Store the shared secret
            if username in connected_users:
                socketio.emit('key_exchange_complete', {'message': 'Key exchange successful'}, to=connected_users[username])
        except Exception as e:
            print(f"Error during key exchange for {username}: {e}")
            import traceback
            traceback.print_exc()

@socketio.on('user_connected')
def handle_user_connected(data):
    username = data.get('username')
    if username:
        connected_users[username] = request.sid
        print(f'{username} connected with sid: {request.sid}')
        socketio.emit('online_users', list(connected_users.keys()), broadcast=True)

@socketio.on('user_disconnected')
def handle_user_disconnected(data):
    username = data.get('username')
    if username in connected_users:
        del connected_users[username]
        print(f'{username} disconnected')
        socketio.emit('online_users', list(connected_users.keys()), broadcast=True)

@socketio.on('send_message')
def handle_message(data):
    iv_base64 = data.get('iv')
    ct = data.get('ct')
    from_user = data.get('from')
    to_user = data.get('to')

    if from_user and from_user in user_keys:
        shared_key_hex = user_keys[from_user]
        try:
            iv = base64.b64decode(iv_base64)
            decrypted_message = decrypt_message(bytes.fromhex(shared_key_hex), f"{iv_base64}:{ct}")
            print(f"Received (Decrypted) from {from_user}{f' to {to_user}' if to_user else ''}: {decrypted_message}")
            message_data = {'iv': iv_base64, 'ct': ct, 'from': from_user}
            if to_user and to_user in connected_users and to_user in user_keys:
                recipient_sid = connected_users[to_user]
                send(message_data, to=recipient_sid)
                print(f"Private message from {from_user} to {to_user} (Relayed)")
            elif not to_user:
                send(message_data, broadcast=True)
                print(f"Broadcast message from {from_user} (Relayed)")
            else:
                print(f"User {to_user} not found or key not exchanged")
        except Exception as e:
            print(f"Error decrypting message on server: {e}")
    else:
        print(f"User {from_user} not found or key not exchanged")

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already exists'}), 400

    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    try:
        db.session.commit()
        return jsonify({'message': 'User registered successfully'})
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error during registration: {e}")
        return jsonify({'error': 'Failed to register user'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid username or password'}), 400

    return jsonify({'message': 'Login successful'})

@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    user_list = [{'id': user.id, 'username': user.username} for user in users]
    return jsonify({'users': user_list})

@app.route('/server_time')
def server_time():
    now = datetime.datetime.now()
    return jsonify({'server_time': now.isoformat()})

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)