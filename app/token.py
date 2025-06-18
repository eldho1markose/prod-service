from fastapi import Depends, HTTPException,Security,status
from fastapi.security import HTTPBearer,HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# Get values from .env
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

auth=HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Security(auth)):
    token=credentials.credentials
    try:
        print("Verifying token...")
        print(f"Token: {token}")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        exp_timestamp = payload.get("exp")
        if exp_timestamp is None or datetime.utcfromtimestamp(exp_timestamp) < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if "sub" not in payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing subject",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload;
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

