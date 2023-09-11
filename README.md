# Flask-Chat 

A simple chat application built with Flask.

## Features

- User registration and authentication
- Chat "shoutbox" where authenticated users can post messages
- SQLite backend for user and message data storage
- Rate limiting
- CSRF protection

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

5. Install required packages:
    ```bash
    pip install -r requirements.txt
    ```

6. Run the application:
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
- Rate limiting has been implemented to prevent brute-force attacks on the login page.
- The application has CSRF protection for forms.

## Contributing

If you'd like to contribute, please fork the repository and make changes as you'd like. Pull requests are warmly welcome.


## Contact

tellhesser33@protonmail.com
Project Link: [https://github.com/justinmaks/flask-chat](https://github.com/justinmaks/flask-chat)



TODO:

- http security headers: Use Flask-Talisman or similar libraries to set security headers like HSTS, X-Frame-Options, etc.
- error handling: Handle potential errors such as database errors, connection issues, or application errors to give users more friendly feedback
- implement logging
- consider prod deployment configuration (debug=True) and others... 
- add admin panel for db/messages/etc
- dockerize
- sockets? 