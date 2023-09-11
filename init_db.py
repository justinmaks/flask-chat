from app import app, db

def init_db():
    with app.app_context():
        # Create tables based on the models
        db.create_all()

if __name__ == "__main__":
    init_db()
    print("Database initialized!")
