import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://postgres:forlan123@localhost:5432/flask_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False