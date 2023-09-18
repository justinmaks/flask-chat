import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from forms import RegisterForm, LoginForm, ShoutboxForm
import logging
from logging.handlers import RotatingFileHandler


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY'),
    SQLALCHEMY_DATABASE_URI='sqlite:///database.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False  # Suppress the modification tracking warning
)

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/flask-chat.log', maxBytes=10240, backupCount=3)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('Flask-Chat startup')


csrf = CSRFProtect(app)

db = SQLAlchemy(app)
 

login_manager = LoginManager(app)
login_manager.login_view = 'login'

#login_manager.session_protection = "strong" #This tells Flask-Login to use strong session protection. When this protection level is set, Flask-Login will monitor the client's IP address and user agent. If either changes, it will log the user out.

limiter = Limiter(
    app=app,
    key_func=lambda: current_user.id if current_user.is_authenticated else request.remote_addr,
    default_limits=["100 per day", "25 per hour"]
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    messages = db.relationship('Message', backref='author', lazy=True)
    # last_ip_address = db.Column(db.String(45))  # storing IP addresses (IPv4 and IPv6)
    # last_user_agent = db.Column(db.String(500)) # storing user agent strings



class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.after_request
def secure_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://ajax.googleapis.com https://maxcdn.bootstrapcdn.com; style-src 'self' https://cdnjs.cloudflare.com https://maxcdn.bootstrapcdn.com https://ajax.googleapis.com"
    return response


@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"404 error encountered. Request path: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(429)
def ratelimit_error(e):
    app.logger.warning(f"Rate limit exceeded by user: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
    return render_template('429.html'), 429



@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("8 per hour")
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        
        if existing_user:
            flash('Username is taken.', 'danger')
            app.logger.warning(f"Attempted registration with taken username: {form.username.data}")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        app.logger.info(f"New user registered: {form.username.data}")

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('shoutbox'))
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(error, 'danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per hour")
def login():
    form = LoginForm()  # Instantiate the form

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):  # Use form.password.data
                login_user(user)
                app.logger.info(f"Successful login for user: {form.username.data}")
                # flash('Login successful.', 'success')
                return redirect(url_for('shoutbox'))
            else:
                flash('Incorrect password. Please try again.', 'danger')  # 'danger' is for Bootstrap error messages
                app.logger.warning(f"Failed login attempt due to incorrect password for user: {form.username.data}")
        else:
            flash('User does not exist. Please check your username or register.', 'danger')
            app.logger.warning(f"Failed login attempt for non-existent user: {form.username.data}")
    return render_template('login.html', form=form)  # Pass the form to the template


@app.route('/logout')
@login_required
def logout():
    user_name = current_user.username
    logout_user()
    app.logger.info(f"User {user_name} logged out.")
    return redirect(url_for('shoutbox'))


@app.route('/', methods=['GET', 'POST'])
@login_required
@limiter.limit("60 per hour") 
def shoutbox():
    form = ShoutboxForm()

    if form.validate_on_submit():
        new_message = Message(content=form.message.data, user_id=current_user.id)
        db.session.add(new_message)
        db.session.commit()

        app.logger.info(f"User {current_user.username} posted a new message.")

        return redirect(url_for('shoutbox'))
    messages = Message.query.order_by(Message.id.desc()).all()

    return render_template('shoutbox.html', messages=messages, form=form)



if __name__ == "__main__":
    app.run(debug=False)
