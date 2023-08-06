import crypt

def generate_password_hash(password, salt):
    return crypt.crypt(password, f"$1${salt}$")

# Example usage:
password = "password"
custom_salt = "test1"

hashed_password = generate_password_hash(password, custom_salt)
print("Hashed password:", hashed_password)

