# models.py or database_models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class UserUsage(db.Model):
    __tablename__ = 'user_usage'

    id = db.Column(db.Integer, primary_key=True)
    #user_id = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.String(50), nullable=False)
    feature_name = db.Column(db.String(50), nullable=False)
    usage_count = db.Column(db.Integer, default=0)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer)
    email_confirmed = db.Column(db.Boolean, default=False)
    payment = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<User {self.username}>"