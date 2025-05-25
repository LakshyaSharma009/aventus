import re

def password_strength(password):
    if len(password) < 8:
        return "Weak password: too short"

    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_special = any(char in "!@#$%^&*()_+-={}[]:;\"',.<>/?\\" for char in password)

    complexity = sum([has_lower, has_upper, has_digit, has_special])

    if complexity < 3:
        return "Weak password: lacks complexity"

    common_patterns = ['123', 'abc', 'password', 'qwerty', '111', 'admin', 'letmein', 'love', 'master', '123456']
    for pattern in common_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return "Weak password: contains common pattern"

    return "Strong password: meets criteria for strength"

password = input("Enter your Password: ")
print(password_strength(password))
