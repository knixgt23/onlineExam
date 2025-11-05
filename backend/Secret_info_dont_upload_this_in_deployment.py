import os

CONFIG = {
    'user': os.getenv('ORACLE_USER'),
    'password': os.getenv('ORACLE_PASSWORD'),
    'dsn': os.getenv('ORACLE_DSN'),
    'encoding': 'UTF-8'
}


JWT_KEY = os.getenv('JWT_KEY', 'fallback-secret-if-not-set')