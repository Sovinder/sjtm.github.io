from password_strength import PasswordPolicy
import secrets
import os

def validate_password(password:str):
    policy = PasswordPolicy.from_names(
        length=8,
        uppercase=1,
        numbers=1,
        special=1,
        nonletters=0,
    )
    return policy.test(password)

def generate_auth_token(length:int):
    token = secrets.token_hex(length)
    return token

def count_files_in_folder(folder_path):
    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        return 0
    return len(os.listdir(folder_path))