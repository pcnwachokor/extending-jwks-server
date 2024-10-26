from datetime import datetime, timedelta, timezone
import pytest
from app import app
import jwt
from flask import Flask

@pytest.fixture
def client():
    with app.test_client() as test:
        yield test

# Should give a valid JWT
def test_Valid_JWT_authentication(client):
    response = client.post('/auth')
    assert response.status_code == 200

# Makes sure that /auth returns an expired JWT
def test_Expired_JWT_authentication(client):
    response = client.post('/auth?expired=true')
    data = jwt.decode(response.get_json().get('token'), '3ba010226cd84939b9eed91aa6bd9519', algorithms=['HS256'], options={"verify_exp": False})
    assert data['exp'] is not None

# Makes sure that valid JWT's kid is found in JWKS
def test_Valid_JWK_Found_In_JWKS(client):
    response = client.post('/auth')
    header = jwt.get_unverified_header(response.get_json().get('token'))
    jwks_keys = client.get('/.well-known/jwks.json').get_json()['keys']
    assert header.get('kid') in [key['kid'] for key in jwks_keys]

# Test to make sure expired JWT's kid is not found in JWKS
def test_Expired_JWK_Not_Found_In_JWKS(client):
    response = client.post('/auth?expired=true')
    header = jwt.get_unverified_header(response.get_json().get('token'))
    jwks_keys = client.get('/.well-known/jwks.json').get_json()['keys']
    assert header.get('kid') not in [key['kid'] for key in jwks_keys]

# Makes sure that JWT exp claim is in the past for expired tokens
def test_Expired_JWK_is_expired(client):
    response = client.post('/auth?expired=true')
    data = jwt.decode(response.get_json().get('token'), '3ba010226cd84939b9eed91aa6bd9519', algorithms=['HS256'], options={"verify_exp": False})
    assert data['exp'] < datetime.now(timezone.utc).timestamp()
