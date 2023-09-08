# flask-chat

Use venv:

python3 -m venv env
source env/bin/activate
pip install -r requirements.txt

sqlite db

deactivate





TODO:
- add better user/login/register error handling
- add base.html with modern theme and modify templates to utilize and extend it
- add rate-limiting (app-level or at infra?)
- http security headers: Use Flask-Talisman or similar libraries to set security headers like HSTS, X-Frame-Options, etc.
- error handling: Handle potential errors such as database errors, connection issues, or application errors to give users more friendly feedback
- implement logging
- consider prod deployment configuration (debug=True) and others... 
- add admin panel for db/messages/etc