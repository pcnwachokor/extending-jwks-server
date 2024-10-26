import base64
from flask import Flask, request, jsonify
import jwt
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

secret_key = '3ba010226cd84939b9eed91aa6bd9519'  # the secret key for encoding
secret_key_bytes = secret_key.encode('utf-8')

base64_encoded_key = base64.urlsafe_b64encode(secret_key_bytes).decode('utf-8')  # this is the base64 encoded key for the jwks

@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired') is not None  # checks if the “expired” query parameter is present

    # payload data
    body = {
        'Fullname': "username",
        'Password': "password",
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(minutes=1)
    }

    if expired:
        # makes the token already expired
        body['exp'] = datetime.now(timezone.utc) - timedelta(seconds=10)  # Expired 10 seconds ago
        token = jwt.encode(body, secret_key, algorithm='HS256', headers={'kid': '3'})  # changes the kid if expired
    else:
        # Sets a future expiration time
        body['exp'] = datetime.now(timezone.utc) + timedelta(hours=1)  # Expires in 1 hour
        token = jwt.encode(body, secret_key, algorithm='HS256', headers={'kid': '1'})

    return jsonify({"token": token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def verify():
    # The JWKS
    jwks_data = {
        "keys": [
            {
                "kty": "oct",
                "alg": "HS256",
                "k": "3ba010226cd84939b9eed91aa6bd9519",
                "kid": "2"
            },
            {
                "kty": "oct",
                "k": base64_encoded_key,
                "alg": "HS256",
                "kid": "1",
                "use": "sig"
            }
        ]
    }
    return jsonify(jwks_data)

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8080)
