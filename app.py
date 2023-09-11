from flask import Flask, render_template, request, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter

app = Flask(__name__)
app.config.update(
    SECRET_KEY='supersecretkey',
    SQLALCHEMY_DATABASE_URI='sqlite:///database.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False  # Suppress the modification tracking warning
)

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

limiter = Limiter(
    app=app,
    key_func=lambda: request.remote_addr, 
    default_limits=["100 per day", "25 per hour"]
)


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
def secure_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com https://ajax.googleapis.com"
    return response


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("8 per hour")
def register():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='sha256')
        new_user = User(username=request.form['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('shoutbox'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per hour")
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user:
            if check_password_hash(user.password, request.form['password']):
                login_user(user)
                return redirect(url_for('shoutbox'))
            else:
                flash('Incorrect password. Please try again.', 'danger')  # 'danger' is for Bootstrap error messages
        else:
            flash('User does not exist. Please check your username or register.', 'danger')
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
        return redirect(url_for('shoutbox'))
    messages = Message.query.order_by(Message.id.desc()).all()
    return render_template('shoutbox.html', messages=messages)


if __name__ == "__main__":
    app.run(debug=True)
