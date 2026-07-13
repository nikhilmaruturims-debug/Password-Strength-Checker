import re
import math

def load_common_passwords():
    """
    Loads the list of common passwords from a text file.
    """
    with open("common_passwords.txt", "r") as file:
        return [line.strip().lower() for line in file]


def check_password_strength(password, username=""):
    """
    Checks the strength of a password based on five security criteria.
    """

    score = 0
    suggestions = []

    common_passwords = load_common_passwords()

    # Check password length
    if len(password) >= 8:
        score += 1
    else:
        suggestions.append("Use at least 8 characters.")

    # Check for uppercase letters
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Add at least one uppercase letter.")

    # Check for lowercase letters
    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Add at least one lowercase letter.")

    # Check for numbers
    if re.search(r"[0-9]", password):
        score += 1
    else:
        suggestions.append("Add at least one number.")

    # Check for special characters
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        suggestions.append("Add at least one special character.")

    # Check if password is a common password
    if password.lower() in common_passwords:
        suggestions.append("This password is commonly used and vulnerable to dictionary attacks.")
        score = max(score - 2, 0)

    # Check for repeated characters
    if re.search(r"(.)\1{2,}", password):
        suggestions.append("Avoid repeated characters in your password.")
        score = max(score - 1, 0)

    # Check for sequential patterns
    sequential_patterns = [
    "12345", "23456", "34567", "45678", "56789",
    "abcdef", "bcdefg", "cdefgh",
    "qwerty", "asdf", "zxcv"
    ]

    password_lower = password.lower()

    for pattern in sequential_patterns:
        if pattern in password_lower:
            suggestions.append("Avoid sequential keyboard or alphabetical patterns.")
            score = max(score - 1, 0)
            break

    # Check for common years in password
    if re.search(r"(19\d{2}|20\d{2})", password):
        suggestions.append("Avoid using years in your password.")
        score = max(score - 1, 0)

    # Check if password contains username
    if username and username.lower() in password.lower():
        suggestions.append("Avoid using your username in the password.")
        score = max(score - 1, 0)

    # Determine password strength
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"
    # Calculate password entropy
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    if charset > 0:
        entropy = len(password) * math.log2(charset)
    else:
        entropy = 0

    return score, strength, suggestions, entropy


print("=" * 45)
print("       PASSWORD STRENGTH CHECKER")
print("=" * 45)

username = input("Enter your username: ")
password = input("Enter a password to check: ")

score, strength, suggestions, entropy = check_password_strength(password, username)

print("\n--- Password Analysis ---")
print(f"Strength: {strength}")
print(f"Security Score: {score}/5")
print(f"Password Entropy: {entropy:.2f} bits")

if suggestions:
    print("\nSuggestions to improve your password:")
    for suggestion in suggestions:
        print(f"- {suggestion}")
else:
    print("\nExcellent! Your password meets all security criteria.")

print("\n" + "=" * 45)