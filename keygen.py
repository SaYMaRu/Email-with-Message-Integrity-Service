import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# User list
users = ["Gong", "Earth", "Joung"] #Can change user name

# Create a users folder if it doesn't exist.
if not os.path.exists("users"):
    os.makedirs("users")

# Function to generate keys for each user
for user in users:
    user_path = os.path.join("users", user)
    os.makedirs(user_path, exist_ok=True)

    # Generate key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Write the private_key.pem file.
    with open(os.path.join(user_path, "private_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write the file public_key.pem
    with open(os.path.join(user_path, "public_key.pem"), "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"Generated key for: {user}")

print("All keys generated successfully.")
