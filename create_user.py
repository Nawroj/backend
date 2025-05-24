from db import SessionLocal
from models.user import User
from utils.security import hash_password

def create_user(username: str, raw_password: str, role: str = "user"):
    db = SessionLocal()
    try:
        hashed_pw = hash_password(raw_password)
        new_user = User(username=username, password=hashed_pw, role=role)
        db.add(new_user)
        db.commit()
        print(f"User '{username}' created successfully!")
    except Exception as e:
        print("Error:", e)
    finally:
        db.close()

if __name__ == "__main__":
    username = input("Enter username: ")
    password = input("Enter password: ")
    role = input("Enter role (default 'user'): ") or "user"
    create_user(username, password, role)
