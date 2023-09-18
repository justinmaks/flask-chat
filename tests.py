import unittest
from app import app, db, User, Message
from werkzeug.security import generate_password_hash


class FlaskChatTestCase(unittest.TestCase):
    
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
        self.app = app.test_client()
        self.app_context = app.app_context()  # Create an application context
        self.app_context.push()  # Push the context so it's active
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_registration(self):
        response = self.app.post('/register', data=dict(
            username="testuser", password="testpass", confirm_password="testpass"
        ), follow_redirects=True)
        self.assertIn(b"Registration successful! You can now log in.", response.data)
        user = User.query.filter_by(username="testuser").first()
        self.assertIsNotNone(user)

    def test_login_logout(self):
        hashed_password = generate_password_hash("testpass", method='sha256')
        user = User(username="testuser", password=hashed_password)
        db.session.add(user)
        db.session.commit()

        response = self.app.post('/login', data=dict(
            username="testuser", password="testpass"
        ), follow_redirects=True)
        self.assertIn(b"Shoutbox", response.data)

        with self.app.session_transaction() as session:
            user_id = session['_user_id']
            self.assertIsNotNone(user_id)

    def test_login_incorrect_password(self):
        hashed_password = generate_password_hash("testpass", method='sha256')
        user = User(username="testuser", password=hashed_password)
        db.session.add(user)
        db.session.commit()

        response = self.app.post('/login', data=dict(
            username="testuser", password="wrongpass"
        ), follow_redirects=True)

        # Checking the flash message for incorrect password.
        self.assertIn(b"Incorrect password. Please try again.", response.data)


    def test_login_nonexistent_user(self):
        response = self.app.post('/login', data=dict(
            username="nonexistentuser", password="somepass"
        ), follow_redirects=True)

        # Checking the flash message for non-existent user.
        self.assertIn(b"User does not exist. Please check your username or register.", response.data)

    def test_post_shoutbox_message(self):
        # Create a test user.
        hashed_password = generate_password_hash("testpass", method='sha256')
        user = User(username="testuser", password=hashed_password)
        db.session.add(user)
        db.session.commit()

        # Log in with the test user.
        self.app.post('/login', data=dict(
            username="testuser", password="testpass"
        ), follow_redirects=True)

        # Post a message to the shoutbox.
        test_message = "This is a unit-test message for the shoutbox"
        response = self.app.post('/', data=dict(
            message=test_message
        ), follow_redirects=True)

        # Check if the message appears on the shoutbox page.
        self.assertIn(bytes(test_message, 'utf-8'), response.data)

        # Verify the message is correctly stored in the database.
        message_in_db = Message.query.filter_by(content=test_message).first()
        self.assertIsNotNone(message_in_db)
        self.assertEqual(message_in_db.author.username, "testuser")

    # def test_rate_limiting(self):
    #     # Assume that no user with username "testuser" exists (so we won't hit database constraints or other app limits)

    #     for _ in range(15):  # making 15 requests
    #         self.app.post('/login', data=dict(
    #             username="testuser", password="wrongpass"
    #         ), follow_redirects=True)
        
    #     # Making the 16th request which should be rate-limited
    #     response = self.app.post('/login', data=dict(
    #         username="testuser", password="wrongpass"
    #     ), follow_redirects=True)

    #     # Checking if we got the "Too Many Requests" response
    #     self.assertEqual(response.status_code, 429)
    #     self.assertIn(b"Rate limit exceeded", response.data)

    def test_routes_require_login(self):
        # Accessing the shoutbox without logging in
        response = self.app.get('/', follow_redirects=False)
        # Expecting a redirect to the login page
        self.assertEqual(response.status_code, 302)  # 302 indicates a redirect
        self.assertIn('/login', response.headers['Location'])

        # Now, logging in a test user
        hashed_password = generate_password_hash("testpass", method='sha256')
        user = User(username="testuser", password=hashed_password)
        db.session.add(user)
        db.session.commit()

        self.app.post('/login', data=dict(
            username="testuser", password="testpass"
        ), follow_redirects=True)

        # Accessing the shoutbox again after logging in
        response = self.app.get('/', follow_redirects=True)
        self.assertEqual(response.status_code, 200)  # 200 indicates a successful response
        self.assertIn(b"Shoutbox", response.data)  # Just to ensure we're on the right page



if __name__ == "__main__":
    unittest.main()
