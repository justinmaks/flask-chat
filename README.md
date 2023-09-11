# Flask-Chat 

A simple chat application built with Flask.

## Features

- User registration and authentication
- Chat "shoutbox" where authenticated users can post messages
- SQLite backend for user and message data storage
- Rate limiting
- CSRF protection using Flask-WTF

## Getting Started

### Prerequisites

Ensure you have the following installed on your local machine:

- Python 3.x
- Pip

### Installation & Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/flask-chat.git
    ```

2. Navigate to the project directory:
    ```bash
    cd flask-chat
    ```

3. Set up a virtual environment:
    ```bash
    python -m venv env
    ```

4. Activate the virtual environment:
    - On Windows:
      ```bash
      .\env\Scripts\activate
      ```

    - On macOS and Linux:
      ```bash
      source env/bin/activate
      ```

5. Install required packages, set env vars:
    ```bash
    pip install -r requirements.txt
    export SECRET_KEY=<yourSecretKey>
    check if debug=True should be set.

    ```

6. Init the dev db (if running for the first time):
    ```bash
    python init_db.py
    ```

7. Run the application:
    ```bash
    python app.py
    ```

Visit `http://127.0.0.1:5000` in your browser to access the application.

## Usage

1. Register for an account.
2. Log in using your credentials.
3. Post messages in the shoutbox.

## Security

- Passwords are securely hashed.
- Rate limiting on login, registration and posts.
- The application has CSRF protection for forms.

## Contributing

If you'd like to contribute, please fork the repository and make changes as you'd like. Pull requests are warmly welcome.


## Contact

tellhesser33@protonmail.com
Project Link: [https://github.com/justinmaks/flask-chat](https://github.com/justinmaks/flask-chat)



TODO:

- html containers 
- input sanitization/maybe flask-wtf does this
- http security headers: Use Flask-Talisman or similar libraries to set security headers like HSTS, X-Frame-Options, etc.
- implement logging
- consider prod deployment configuration (debug=True) and others... 
- add admin panel for db/messages/etc
- dockerize
- sockets? 


## prod deploy 

###

Install and enable nginx

sudo nano /etc/nginx/sites-available/flask-chat
sudo ln -s /etc/nginx/sites-available/flask-chat /etc/nginx/sites-enabled


 ```bash
 server {
    listen 80;
    server_name your_domain_or_ip;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

 ```

 make sure gunicorn is installed GLOBALLY


 run it: 
 ```bash
 nohup gunicorn app:app &
 ```