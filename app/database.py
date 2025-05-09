from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL="postgresql://user:pass@db:5432/productdb"

engine=create_engine(SQLALCHEMY_DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine,autocommit=False,autoflush=False,)

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()