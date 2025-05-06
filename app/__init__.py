# app/__init__.py
from flask import Flask
from config import Config
from utils.logger import Logger

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Khởi tạo logger
    app.logger = Logger()
    
    # Import và đăng ký blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)
    
    return app