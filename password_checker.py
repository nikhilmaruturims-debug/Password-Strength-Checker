import re


def check_password_strength(password):
    """
    Checks the strength of a password based on five security criteria.
    """

    score = 0
    suggestions = []

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

    # Determine password strength
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return score, strength, suggestions


print("=" * 45)
print("       PASSWORD STRENGTH CHECKER")
print("=" * 45)

password = input("\nEnter a password to check: ")

score, strength, suggestions = check_password_strength(password)

print("\n--- Password Analysis ---")
print(f"Strength: {strength}")
print(f"Security Score: {score}/5")

if suggestions:
    print("\nSuggestions to improve your password:")
    for suggestion in suggestions:
        print(f"- {suggestion}")
else:
    print("\nExcellent! Your password meets all security criteria.")

print("\n" + "=" * 45)