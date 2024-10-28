import base64
from flask import Flask, request, jsonify
import jwt
import time
import sqlite3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk

app = Flask(__name__)

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    ''')
    cursor.execute("DELETE FROM keys")  # Clear table on startup for clean testing
    conn.commit()
    conn.close()

# Store a key in the database
def store_key(private_key, expiry):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    pem_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem_key, expiry))
    conn.commit()
    conn.close()

     #Generate and store initial keys
def initialize_keys():
    # Key that expires in the past
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store_key(expired_key, int(time.time()) - 3600)  # 1 hour in the past
    
    # Key that expires in the future
    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    store_key(valid_key, int(time.time()) + 3600)  # 1 hour in the future


    # Retrieve a key from the database based on expiry
def get_key(expired):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    if expired:
        cursor.execute("SELECT kid, key FROM keys WHERE exp < ?", (int(time.time()),))
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(time.time()),))
    result = cursor.fetchone()
    conn.close()
    if result:
        kid, pem_key = result
        private_key = serialization.load_pem_private_key(pem_key, password=None)
        return kid, private_key
    return None, None

# JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (int(time.time()),))
    keys = []
    for row in cursor.fetchall():
        kid, pem_key = row
        private_key = serialization.load_pem_private_key(pem_key, password=None)
        public_key = private_key.public_key()
        
        # Convert to JWK format
        jwk_key = jwk.JWK.from_pem(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        jwk_key_obj = jwk_key.export(as_dict=True)
        jwk_key_obj['kid'] = str(kid)  
        keys.append(jwk_key_obj)
    conn.close()
    return jsonify({"keys": keys}), 200


# Auth endpoint to issue a JWT
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired', 'false') == 'true'
    kid, private_key = get_key(expired)
    if private_key is None:
        return jsonify({"error": "No appropriate key found"}), 404

    expiry_time = time.time() - 3600 if expired else time.time() + 3600
    print(f"JWT kid: {kid}")
    token = jwt.encode(
        {
            'sub': 'userABC',
            'exp': expiry_time
        },
        private_key,
        algorithm='RS256',
        headers={"kid": str(kid)}  # Set 'kid' in the JWT header
    )
    return jsonify({"token": token}), 200


if __name__ == "__main__":
    init_db() #initialize database
    initialize_keys() #initialize keys
    app.run(host='127.0.0.1', port=8080)
