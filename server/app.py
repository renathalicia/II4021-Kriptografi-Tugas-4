from flask import Flask
from server.db.database import init_db
from server.routes.vault_routes import vault_bp

def create_app() -> Flask:
    app = Flask(__name__)
    init_db()
    app.register_blueprint(vault_bp)
    return app

if __name__ == "__main__":
    from server.config import HOST, PORT, DEBUG
    app = create_app()
    app.run(host=HOST, port=PORT, debug=DEBUG)
