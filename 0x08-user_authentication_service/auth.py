#!/usr/bin/env python3
"This is a line of text"
from db import DB
import bcrypt
import uuid
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError


def _hash_password(password: str) -> str:
    "This is a line of text"
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    "This is a line of text"
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        "This is a line of text"
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        "This is a line of text"
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> str:
        "This is a line of text"
        user = self._db.find_user_by(email=email)
        if user:
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id

    def get_user_from_session_id(self, session_id: str) -> str:
        "This is a line of text"
        try:
            return self._db.find_user_by(session_id=session_id)
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        "This is a line of text"
        if user_id:
            self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        "This is a line of text"
        if email:
            user = self._db.find_user_by(email=email)
            if not user:
                raise ValueError
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        "This is a line of text"
        if reset_token and password:
            user = self._db.find_user_by(reset_token=reset_token)
            if user:
                hashed_password = _hash_password(password)
                self._db.update_user(user.id, hashed_password=hashed_password,
                                     reset_token=None)
            else:
                raise ValueError
