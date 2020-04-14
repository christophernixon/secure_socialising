from flask import Flask, redirect, make_response, request, render_template, session
from flask_restful import Api
from cryptography.fernet import Fernet
from flask_jwt_extended import (JWTManager, jwt_required, 
                                jwt_refresh_token_required,
                                verify_jwt_in_request_optional, 
                                jwt_optional, fresh_jwt_required, 
                                get_raw_jwt, get_jwt_identity,
                                create_access_token, create_refresh_token, 
                                set_access_cookies, set_refresh_cookies, 
                                unset_jwt_cookies,unset_access_cookies)
from datetime import timedelta
from app.services import (validate_password,hash_password, generate_board_key)
from typing import List, Dict
import hashlib 
import random 
import string
import os

key = Fernet.generate_key()
cipher_suite = Fernet(key)

app = Flask(__name__)
app.secret_key = 'secret key'
app.config['BASE_URL'] = 'http://127.0.0.1:5000'  #Running on localhost
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(seconds = 120)
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['PROPAGATE_EXCEPTIONS'] = True
jwt = JWTManager(app)

user_database: Dict[str, Dict[str, str]] = {}
message_database: List[str] = []
message_boards: Dict[str, Dict[str, List[str]]] = {'Default Board': {'messages':[],'board_topic':['default'], 'key':[], 'members':[]}}
passwords: Dict[str, tuple] = {}

@jwt.unauthorized_loader
def unauthorized_callback(callback):
    # No auth header
    return redirect(app.config['BASE_URL'] + '/', 302)

@jwt.invalid_token_loader
def invalid_token_callback(callback):
    # Invalid Fresh/Non-Fresh Access token in auth header
    resp = make_response(redirect(app.config['BASE_URL'] + '/'))
    unset_jwt_cookies(resp)
    return resp, 302

@jwt.expired_token_loader
def expired_token_callback(callback):
    # Expired auth header
    resp = make_response(redirect(app.config['BASE_URL'] + '/token/refresh'))
    unset_access_cookies(resp)
    return resp, 302

@app.route('/token/refresh', methods=['GET'])
@jwt_refresh_token_required
def refresh():
    # Refreshing expired Access token
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=str(user_id))
    resp = make_response(redirect(app.config['BASE_URL'] + '/', 302))
    set_access_cookies(resp, access_token)
    return resp

def assign_access_refresh_tokens(user_id, url):
    access_token = create_access_token(identity=str(user_id), fresh = True)
    refresh_token = create_refresh_token(identity=str(user_id))
    resp = make_response(redirect(url, 302))
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp

def unset_jwt():
    resp = make_response(redirect(app.config['BASE_URL'] + '/', 302))
    unset_jwt_cookies(resp)
    return resp

@app.route('/account')
@fresh_jwt_required
def account():
    # very important account settings 
    username = get_jwt_identity()
    print("Username: ",username)
    return render_template('account.html'), 200

@app.route('/services', methods=['GET'])
@jwt_required
def services():
    # Not important stuff but still needs to be logged in 
    username = get_jwt_identity()
    print("Username: ",username)
    return render_template('services.html'), 200

@app.route('/changeboard', methods=['POST'])
def changeboard():
    post_data = request.form.to_dict()
    new_visible_board = post_data['requested_board']
    if new_visible_board == 'Default':
        session['visible_board'] = "Default Board"
    else:
        session['visible_board'] = new_visible_board
    # visible_board = new_visible_board
    return redirect('/messages')

@app.route('/addmember', methods=['POST'])
def addmember():
    post_data = request.form.to_dict()
    selected_member = post_data['memberselection']
    current_user = session['current_user']
    current_board = session['visible_board']
    if selected_member != current_user:
        member_list = message_boards[current_board]['members']
        if selected_member not in member_list:
            member_list.append(selected_member)
        message_boards[current_board]['members'] = member_list
        # Add access to member
        add_board_access(selected_member, current_board)

    return redirect('/messages')

@app.route('/removemember', methods=['POST'])
def removemember():
    post_data = request.form.to_dict()
    selected_member = post_data['memberselection']
    current_user = session['current_user']
    current_board = session['visible_board']
    if selected_member != current_user:
        member_list = message_boards[current_board]['members']
        if selected_member in member_list:
            member_list.remove(selected_member)
        message_boards[current_board]['members'] = member_list
        # Revoke access from member
        revoke_access(selected_member, current_board)
    return redirect('/messages')

@app.route('/addmessage', methods=['POST'])
def addmessage():
    # Authenticated, so message can be added to board.
    username = get_jwt_identity()
    result = request.form.to_dict()
    message = result['message']
    if 'visible_board' in session:
        visible_board = session['visible_board']
    else:
        visible_board = "Default Board"
    message_boards[visible_board]['messages'].append(cipher_suite.encrypt(bytes(message, 'utf-8')))
    # message_database.append(cipher_suite.encrypt(bytes(message, 'utf-8')))
    return redirect('/messages')

@app.route('/homepage', methods=['GET'])
@jwt_optional
def homepage():
    """Initial page for the application."""
    username = get_jwt_identity()
    # If username saved in cookie, display logging in user in Menu Bar.
    if username and 'current_user' in session:
            return render_template('homepage.html', current_user=session['current_user']), 200
    return render_template('homepage.html'), 200

@app.route('/newboard', methods=['GET','POST'])
def newboard():
    # If GET, simply render page.
    if request.method == 'GET':
        verify_jwt_in_request_optional()
        username = get_jwt_identity()
        if username and 'current_user' in session:
            return render_template('newboard.html',current_user=session['current_user']), 200
        else:
            return render_template('newboard.html'), 200
    # If POST, fetch and verify the post data
    post_data = request.form.to_dict()
    board_name = post_data['board_name']
    board_topic = post_data['board_topic']
    # Create a new board
    board_key = generate_board_key()
    message_boards[board_name] = {'messages': [], 'board_topic': [board_topic], 'key': [board_key], 'members': [session['current_user']]}
    # Add access to user who created the board
    current_user = session['current_user']
    current_user_email = get_email_from_username(current_user)
    user_database[current_user_email]['boards'].append(board_key)
    return redirect(app.config['BASE_URL'] + '/messages', 302)

@app.route('/messages', methods=['GET'])
@jwt_optional
def messages():
    username = get_jwt_identity()
    if 'visible_board' in session:
        board_title = session['visible_board']
    else:
        board_title = "Default Board"
    board_info = message_boards[board_title]
    messages = message_boards[board_title]['messages']
    boardnames = message_boards.keys()
    all_users = get_all_users()

    if board_title == "Default Board":
        decrypted_messages = get_decrypted_messages(board_title)
        return render_template('messages.html', current_user=session['current_user'], board_access=False, input_access=True, all_users=all_users, board_title=board_title, board_info=board_info, boardnames=boardnames, messages=decrypted_messages), 200
    elif username and 'current_user' in session and has_access(session['current_user'], board_title):
        decrypted_messages = get_decrypted_messages(board_title)
        return render_template('messages.html', current_user=session['current_user'], board_access=True, input_access=True, all_users=all_users, board_title=board_title, board_info=board_info, boardnames=boardnames, messages=decrypted_messages), 200
    else:
        encrypted_messages = get_encrypted_messages(board_title)
        return render_template('messages.html', current_user=session['current_user'], board_access=False, input_access=False, board_title=board_title, board_info=board_info, boardnames=boardnames, messages=encrypted_messages), 200
       

@app.route('/register', methods=['GET','POST'])
def register():
    """Register a new user of the application."""
    # If GET, simply render register page.
    if request.method == 'GET':
        return render_template('register.html'), 200

    # If POST, fetch and verify the post data 
    # username = get_jwt_identity()
    post_data = request.form.to_dict()
    user_email = post_data['email']
    user_id = check_for_email(user_email)
    if user_id:
        # User already exists, so display error and option to go to login page.
        return render_template('register.html', existing_user=True), 402
    else:
        # Add user to user database and grant access rights.
        username = post_data['username']
        password = post_data['password']
        add_user(user_email, username, password)
        session['current_user'] = username
        return assign_access_refresh_tokens(username, app.config['BASE_URL'] + '/homepage')

@app.route('/')
def index():
    """Initial page for the application."""
    return render_template('index.html'), 200

@app.route('/login', methods=['GET','POST'])
def login():
    """Login user."""
    # If GET, simply render login page.
    if request.method == 'GET':
        return render_template('login.html'), 200
    
    # If POST, fetch and verify the post data
    post_data = request.form.to_dict()
    username = post_data['username']
    user_id = check_for_username(username)
    if user_id:
        # Fetch and verify password
        password = post_data['password']
        if check_password(user_id, password):
            # Save username as cookie to display in Menu Bar, grant JWT
            session['current_user'] = username
            return assign_access_refresh_tokens(username, app.config['BASE_URL'] + '/homepage')
    # If no user_id or invalid password, display error on login page.
    return render_template('login.html', invalid_login=True)

@app.route('/logout')
@jwt_required
def logout():
    # session['current_user'] = None
    session['current_user'] = None
    session['visible_board'] = "Default Board"
    # if 'current_user' in session:
    #     session.pop('current_user')
    # if 'visible_board' in session:
    #     session.pop('visible_board')
    # Revoke Fresh/Non-fresh Access and Refresh tokens
    return unset_jwt(), 302

def get_decrypted_messages(board_name):
    messages = message_boards[board_name]['messages']
    decrypted_messages = []
    for message in messages:
        decrypted_messages.append(cipher_suite.decrypt(message).decode("utf-8"))
    return decrypted_messages

def get_encrypted_messages(board_name):
    messages = message_boards[board_name]['messages']
    encrypted_messages = []
    for message in messages:
        encrypted_messages.append(message.decode("utf-8"))
    return encrypted_messages

def add_user(email, username, password):
    """Add a user to the user database."""
    # Find max user id
    max_id = 0
    for tmp_email in user_database:
        if user_database[tmp_email]['id'] > max_id:
            max_id = user_database[tmp_email]['id']
    
    user_id = max_id + 1
    # Add user to database
    tmp_dict: Dict[str, str] = {}
    tmp_dict['id'] = user_id
    tmp_dict['username'] = username
    tmp_dict['boards'] = []
    user_database[email] = tmp_dict
    (hashed_pass, salt) = hash_password(password, iterations=50)
    passwords[user_id] = (hashed_pass, salt)
    add_member_to_default_board(username)

def add_member_to_default_board(username):
    board_members = message_boards["Default Board"]['members']
    board_members.append(username)
    message_boards["Default Board"]['members'] = board_members

def check_for_username(username):
    """Check user database for a particular username, if found return associated user id."""
    for email in user_database:
        if user_database[email]['username'] == username:
            return user_database[email]['id']
    return None

def get_all_users():
    all_users = []
    for user_id in user_database:
        all_users.append(user_database[user_id])
    return all_users

def revoke_access(username, board_name):
    user_email = get_email_from_username(username)
    if user_email:
        board_key = message_boards[board_name]['key'][0]
        user_board_keys = user_database[user_email]['boards']
        if board_key in user_board_keys:
            user_board_keys.remove(board_key)
        user_database[user_email]['boards'] = user_board_keys
        return True
    return False

def add_board_access(username, board_name):
    user_email = get_email_from_username(username)
    if user_email:
        board_key = message_boards[board_name]['key'][0]
        user_board_keys = user_database[user_email]['boards']
        user_board_keys.append(board_key)
        user_database[user_email]['boards'] = user_board_keys
        return True
    return False

def get_email_from_id(user_id):
    for email in user_database:
        if user_database[email]['id'] == user_id:
            return email
    return None

def get_email_from_username(username):
    for email in user_database:
        if user_database[email]['username'] == username:
            return email
    return None

def check_for_email(email):
    """Check user database for a particular email, if found return associated user id."""
    if email in user_database:
        return user_database[email]['id']
    else:
        return None

def has_access(username, board_name):
    if board_name == "Default Board":
        return True
    user_email = get_email_from_username(username)
    if user_email:
        user_board_keys = user_database[user_email]['boards']
        for key in user_board_keys:
            if key == message_boards[board_name]['key'][0]:
                return True
    return False

def check_password(user_id, password):
    """Check that given password is correct for given user_id."""
    for id in passwords:
        if id == user_id:
            (pw_hash,pw_salt) = passwords[id]
            return validate_password(password, (pw_hash,pw_salt))
    return False
