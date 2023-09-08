from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress the modification tracking warning

csrf = CSRFProtect(app)  # Initialize CSRF protection

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    messages = db.relationship('Message', backref='author', lazy=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.after_request
def add_csp(response):
    # This is a very strict policy 
    # It allows only scripts from the same origin and inline styles.
    # You can modify this according to your requirements.
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return response

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(username=request.form['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('shoutbox'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('shoutbox'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('shoutbox'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def shoutbox():
    if request.method == 'POST':
        new_message = Message(content=request.form['message'], user_id=current_user.id)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('shoutbox'))  # Redirect after POST to prevent form resubmission
    messages = Message.query.order_by(Message.id.desc()).all()  # Ordering messages so latest messages come first
    return render_template('shoutbox.html', messages=messages)

if __name__ == "__main__":
    app.run(debug=True)
