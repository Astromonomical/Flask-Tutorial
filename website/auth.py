from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User, User_Roles
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form.get('name')
        password = request.form.get('password')

        user = User.query.filter_by(name=name).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Password incorrect. Please try again.', category='error')
        else:
            flash('Name does not exist.', category='error')

    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        name = request.form.get('name')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        if request.form.get('admin'):
            role_id = 0
        else:
            role_id = 1

        user = User.query.filter_by(name=name).first()

        if user:
            flash('Name already exists', category='error')
        elif len(name) < 3:
            flash('Name must be greater than 2 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 characters.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        elif len(password1) < 7:
            flash('Password length must be greater than 6.', category='error')
        else:
            # Add new user account
            new_user = User(name=name, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()

            # Update user roles
            user = User.query.filter_by(name=name).first()
            new_role = User_Roles(user_id=user.id, role_id=role_id)
            db.session.add(new_role)
            db.session.commit()

            # Flash message and move to home
            flash('Account created!', category='success')
            return redirect(url_for('views.home'))

    return render_template("signup.html", user=current_user)