import pytest
import time
from app import app, init_db, initialize_keys
import jwt
import sqlite3

@pytest.fixture
def client():
    # Initialize the database and insert keys before each test
    init_db()
    initialize_keys()
    
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_jwks(client):
    # Test to check if the JWKS endpoint returns non-expired keys
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    data = response.get_json()
    assert 'keys' in data
    assert len(data['keys']) > 0  # Ensure at least one valid key is present

def test_auth_valid_token(client):
    # Test to ensure a valid JWT is returned
    response = client.post('/auth')
    assert response.status_code == 200
    data = response.get_json()
    token = data['token']
    assert token  # Ensure a token is returned

    # Decode and check expiration time
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded['exp'] > time.time()  # Token should be valid (not expired)

def test_auth_expired_token(client):
    # Test to ensure an expired JWT is returned when requested
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    data = response.get_json()
    token = data['token']
    assert token  # Ensure a token is returned even if expired

    # Decode and check expiration time
    decoded = jwt.decode(token, options={"verify_signature": False})
    assert decoded['exp'] < time.time()  # Token should be expired

def test_database_key_storage():
    # Verify the keys are correctly stored in the SQLite database
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM keys")
    keys = cursor.fetchall()
    conn.close()
    assert len(keys) >= 2  # Ensure at least two keys (one expired, one valid) are stored