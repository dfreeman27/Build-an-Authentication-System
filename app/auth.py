

import bcrypt
from jose import jwt, JWTError
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User


SECRET_KEY = "dev-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


http_bearer = HTTPBearer()


def hash_password(password: str) -> str:
    """Returns the bcrypt hash of the given plain-text password."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")



def verify_password(plain: str, hashed: str) -> bool:
    """Returns True if plain matches the hashed password."""
    return False if len(plain.encode("utf-8")) > 72 else bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))



def create_access_token(data: dict) -> str:
    """Creates a signed JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# TODO: Implement get_current_user(credentials, db) — a FastAPI dependency
# 1. Extract the token string: token = credentials.credentials
# 2. Try to decode the token: jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
# 3. Extract "sub" (subject = username) from the payload
# 4. Look up the user in the DB
# 5. Raise 401 if any step fails
#
# Key concept: Security(get_current_user) on an endpoint means FastAPI will
# call this function first and inject its return value. If the function raises
# an exception, the endpoint never runs — the error is returned instead.
def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(http_bearer),
    db: Session = Depends(get_db),
):
    """
    Dependency that extracts and validates the JWT, returning the current user.

    TODO:
    1. credentials_exception = HTTPException(401, ...)
    2. try: payload = jwt.decode(...)
    3. username = payload.get("sub") — raise if None
    4. Look up user by username in DB — raise if not found
    5. return user
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    return user