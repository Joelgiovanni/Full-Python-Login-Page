from flask import Flask, render_template, url_for, redirect, flash, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

app = Flask(__name__)
app.config['SECRET_KEY'] = 'WFSEDGFHF#$%^%$#@#$%$#@#$#@#ERGF'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/joelgodoy/Desktop/login-pages/social2/database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(14), unique=True)
    email = db.Column(db.String(60), unique=True)
    password = db.Column(db.String(60))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=4, max=14)])
    password = PasswordField('password', validators=[DataRequired(), Length(min=4, max=80)])

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=4, max=14)])
    email = StringField('email', validators=[DataRequired(), Email(message='Invalid Email'), Length(max=60)])
    password = PasswordField('password', validators=[DataRequired(), Length(min=4, max=80)])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('welcome'))
        error = 'Invalid username or password. Please try again.'
    return render_template('login.html', form=form, error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('newuser'))
    return render_template('signup.html', form=form, error=error)

@app.route('/welcome')
@login_required
def welcome():
    return render_template('welcome.html', name=current_user.username)

@app.route('/newuser')
def newuser():
    return render_template('newuser.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)