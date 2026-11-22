import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from backend root or parent
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

class Settings:
    PROJECT_NAME: str = "ScamShield AI"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api"
    
    # API Keys (Loaded securely from environment or .env)
    URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    
    # Google OAuth (Provide new credentials via .env when ready)
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "scamshield_dev_jwt_secret_key")
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # Database
    MONGODB_URI: str = os.getenv("MONGODB_URI", "mongodb://localhost:27017/scamshield")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "scamshield")
    
    # Server / CORS
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")

settings = Settings()
