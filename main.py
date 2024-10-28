from flask import Flask, jsonify, request, abort
import sqlite3
import jwt
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import base64

# Flask app setup
app = Flask(__name__)
ALGORITHM = "RS256"

# Database connection
def get_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database with the required table
def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
        """)

# Generate and serialize an RSA private key in PEM format
def generate_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem

# Save a generated private key to the database with an expiration timestamp
def save_key(key, exp):
    with get_db() as conn:
        conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key, exp))

# Function to sign a JWT with the private key and include `kid` in the header
def generate_jwt(payload, private_key, kid):
    headers = {"kid": str(kid)}
    return jwt.encode(payload, private_key, algorithm=ALGORITHM, headers=headers)

# Endpoint to authenticate and return a JWT
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get("expired")
    with get_db() as conn:
        if expired:
            row = conn.execute("SELECT * FROM keys WHERE exp < ?", 
                               (int(datetime.datetime.now().timestamp()),)).fetchone()
        else:
            row = conn.execute("SELECT * FROM keys WHERE exp > ?", 
                               (int(datetime.datetime.now().timestamp()),)).fetchone()
    
    if not row:
        abort(404, description="No appropriate key found")
    
    payload = {
        "user": "userABC",
        "iat": datetime.datetime.now().timestamp(),
        "exp": row['exp']
    }
    token = generate_jwt(payload, row['key'], row['kid'])  # Pass `kid` to JWT header
    return jsonify(token=token)

# Endpoint to provide JWKS (JSON Web Key Set) data
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM keys WHERE exp > ?", 
                            (int(datetime.datetime.now().timestamp()),)).fetchall()
    
    # Convert each key to a JWK format
    keys = []
    for row in rows:
        public_key = serialization.load_pem_private_key(
            row["key"],
            password=None,
            backend=default_backend()
        ).public_key()
        
        # Get public numbers
        public_numbers = public_key.public_numbers()
        
        # Base64 encode 'n' and 'e'
        n = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
        e = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
        
        keys.append({
            "kid": str(row["kid"]),
            "kty": "RSA",
            "use": "sig",
            "alg": ALGORITHM,
            "n": n,
            "e": e
        })
    
    return jsonify({"keys": keys})

# Initialize and populate the database with sample keys
if __name__ == '__main__':
    init_db()  # Create the database if it doesn't exist
    # Generate and save an expired and a valid key for testing
    save_key(generate_private_key(), int((datetime.datetime.now() - datetime.timedelta(hours=1)).timestamp()))  # Expired key
    save_key(generate_private_key(), int((datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp()))  # Unexpired key
    app.run(port=8080)

