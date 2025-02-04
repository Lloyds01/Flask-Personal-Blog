from flask import render_template, redirect, url_for, flash, request
from app import db
from app.models import User
from app.forms import RegistrationForm, LoginForm
from flask_login import login_user, logout_user, current_user
from flask import Blueprint
from flask import jsonify

main_routes = Blueprint('main', __name__)
auth_routes = Blueprint('auth', __name__)

@main_routes.route('/', methods=['GET'])
def home():
    return render_template('index.html')
    # return jsonify({"message": "Hello, World!"})


@auth_routes.route('/register', methods=['POST'])
def register():
    # Check if the user is already authenticated
    if current_user.is_authenticated:
        return jsonify({"error": "You are already logged in."}), 400

    # Parse JSON data from the request
    data = request.get_json()

    # Manually validate the data (since we're not using Flask-WTF forms for API endpoints)
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"error": "Missing required fields (username, email, password)."}), 400

    # Check if the username or email already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists."}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already exists."}), 400

    # Create a new user
    user = User(
        username=data['username'],
        email=data['email'],
        password=data['password']  # Note: You should hash the password before saving it
    )

    # Add the user to the database
    db.session.add(user)
    db.session.commit()

    # Return the created user details as a JSON response
    return jsonify({
        "message": "Account created successfully!",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            # Do not return the password for security reasons
        }
    }), 201

# @auth_routes.route('/register', methods=['GET', 'POST'])
# def register():
#     if current_user.is_authenticated:
#         return redirect(url_for('main.home'))
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         user = User(username=form.username.data, email=form.email.data, password=form.password.data)
#         db.session.add(user)
#         db.session.commit()
#         flash('Account created successfully!', 'success')
#         return redirect(url_for('auth.login'))
#     return render_template('register.html', form=form)

@auth_routes.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('main.home'))
        flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)

@auth_routes.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.home'))


@auth_routes.route('/test-db')
def test_db():
    try:
        users = User.query.all()
        return jsonify([user.username for user in users])
    except Exception as e:
        return jsonify({"error": str(e)}), 500