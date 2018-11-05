from flask import Flask, render_template, session, request, redirect, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'haha'
password_regex = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])[A-Za-z\d$@$!%*?&]{8,}")
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    if 'first_name' not in session:
        session['first_name'] = ''
    if 'last_name' not in session:
        session['last_name'] = ''
    if 'email' not in session:
        session['email'] = ''
    if 'password' not in session:
        session['password'] = ''
    if 'pass_confirm' not in session:
        session['pass_confirm'] = ''
    return render_template('index.html')

@app.route('/create', methods=['post'])
def process():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password= request.form['password']
    pass_confirm = request.form['pass_confirm']

    if first_name == '':
        flash('First Name cannot be blank!', 'first_name')
        return redirect('/')

    elif last_name == '':
        flash('Last Name cannot be blank!', 'last_name')
        return redirect('/')

    elif email == '':
        flash('Email cannot be blank!', 'email')
        return redirect('/')

    elif not email_regex.match(email):
        flash('Invalid email address', 'email')
        return redirect('/')

    elif password == '':
        flash('Password cannot be blank!', 'password')
        return redirect('/')

    elif not password_regex.match(password):
        flash('Please enter a password with a minimum of eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:', 'password')
        return redirect('/')

    elif pass_confirm == '':
        flash('This cannot be blank!', 'pass_confirm')
        return redirect('/')

    elif password != pass_confirm:
        flash('Passwords must match!', 'pass_confirm')
        return redirect('/')

    session['first_name'] = first_name
    session['last_name'] = last_name
    session['email'] = email
    session['password'] = password
    session['pass_confirm'] = pass_confirm

    pw_hash = bcrypt.generate_password_hash(password)
    mysql = connectToMySQL('login_register')
    query = 'INSERT INTO users (first_name, last_name, email, password, created_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(pw_hash)s, NOW());'
    data = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'pw_hash': pw_hash
    }
    table = mysql.query_db(query, data)
    session['password'] = ''
    session['pass_confirm'] = ''

    return redirect('/dashboard')

@app.route('/validate', methods=['post'])
def login_validate():
    email = request.form['email_login']
    password = request.form['password_login']
    # password_hash = bcrypt.generate_password_hash(password)
    mysql = connectToMySQL('login_register')
    query = 'SELECT email, password FROM users WHERE email=%(email)s;'
    data = {
        'email': email,
    }
    login = mysql.query_db(query, data)
    print(login)
    if bcrypt.check_password_hash(login[0]['password'], password):
        return redirect('/dashboard')
    else:
        flash('Incorrect Password', 'password_error')
        return redirect('/')

@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

@app.route('/logout', methods=['post'])
def logout():
    session['first_name'] = ''
    session['last_name'] = ''
    session['email'] = ''
    session['password'] = ''
    session['pass_confirm'] = ''
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
