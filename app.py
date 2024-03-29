from flask import Flask, request, jsonify, make_response, render_template, session
from flask_pymongo import PyMongo
import jwt
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
from flask import redirect, flash,url_for

app = Flask(__name__)

# Configure MongoDB connection
app.config['MONGO_URI'] = 'mongodb://localhost:27017/users_db'
mongo = PyMongo(app)

app.config['SECRET_KEY'] = 'c00b4560c37c42d69c9d3236a7033540'

def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'Alert!': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'Message': 'Token has expired'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'Message': 'Invalid token'}), 403
        return func(*args, **kwargs)
    return decorated

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/public')
def public():
    return 'For Public'

@app.route('/auth')
@token_required
def auth():
    return 'JWT is verified. Welcome to your dashboard!'

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/login', methods=['POST'])
def login_post():
    users = mongo.db.users
    username = request.form['username']
    password = request.form['password']
    user = users.find_one({'username': username})
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        session['logged_in'] = True
        # Redirect to welcome page
        return redirect(url_for('welcome'))
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm: "Authentication Failed "'})
    
@app.route('/signup', methods=['POST'])
def signup_post():
    users = mongo.db.users
    username = request.form['username']
    password = request.form['password']
    if users.find_one({'username': username}):
        return make_response('Username already exists', 400)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users.insert_one({'username': username, 'password': hashed_password})
    flash('User registered successfully', 'success')
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
