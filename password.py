import hashlib

# -----------------------
# Password Validation
# -----------------------
def check_password(password):
    reasons = []

    if len(password) < 8:
        reasons.append("Minimum length is 8 characters")

    if not any(c.isupper() for c in password):
        reasons.append("Must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        reasons.append("Must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        reasons.append("Must contain at least one number")

    special_chars = "!@#$%^&_"
    if not any(c in special_chars for c in password):
        reasons.append("Must contain at least one special character")

    if reasons:
        return False, reasons
    else:
        return True, []


# -----------------------
# Generate SHA256 Hash
# -----------------------
def generate_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


# -----------------------
# JWT Secret Validation
# -----------------------
def check_jwt(secret):
    reasons = []

    weak_values = ["admin", "123456", "password", "secret", "jwtsecret"]

    if len(secret) < 16:
        reasons.append("Minimum length is 16 characters")

    if not any(c.isupper() for c in secret):
        reasons.append("Must contain uppercase letters")

    if not any(c.islower() for c in secret):
        reasons.append("Must contain lowercase letters")

    if not any(c.isdigit() for c in secret):
        reasons.append("Must contain numbers")

    special_chars = "!@#$%^&_"
    if not any(c in special_chars for c in secret):
        reasons.append("Must contain special characters")

    if secret.lower() in weak_values:
        reasons.append("This is a common weak value")

    if reasons:
        return False, reasons
    else:
        return True, []


# -----------------------
# Main Program (CLI)
# -----------------------
password = input("Enter Password: ")

is_strong, reasons = check_password(password)

if not is_strong:
    print("Password is weak")
    for r in reasons:
        print("-", r)
else:
    print("Password is strong")
    print("Hash:", generate_hash(password))


jwt = input("\nEnter JWT Secret: ")

is_strong_jwt, reasons_jwt = check_jwt(jwt)

if not is_strong_jwt:
    print("JWT Secret is weak")
    for r in reasons_jwt:
        print("-", r)
else:
    print("JWT Secret is strong")