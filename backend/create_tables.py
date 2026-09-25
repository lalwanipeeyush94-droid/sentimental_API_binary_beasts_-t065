from app.database import engine
from app.models import Base


if __name__ == "__main__":
    print("Creating missing database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database tables ready.")