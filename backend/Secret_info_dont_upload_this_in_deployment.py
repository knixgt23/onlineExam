import os

DATABASE_URL = os.getenv("DATABASE_URL")  # This is from Render environment variable

JWT_KEY = os.getenv("JWT_KEY", "fallback-secret-if-not-set")
