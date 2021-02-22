from flask import Flask, request, jsonify, render_template, redirect, url_for
import uuid
import jwt
import datetime
from functools import wraps
from user_model import UserModel
import re
import md5


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key'

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = None
        token = kwargs['data'] 
        if not token:  
          return jsonify({'message': 'a valid token is missing'})  
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = UserModel().get(data['phone'])
        except:
             return jsonify({'message': 'token is invalid'}) 
        return f(current_user)
    return wrapper


@app.route('/', methods=['GET', 'POST'])
def home():
    error = None
    print 'home'
    return render_template('home.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register(): 
    """
    registers the user in the database
    """
    error = None
    if request.method == 'POST': 
        password = request.form['password']  
        phone = request.form['phone']
        if not __check_phone_number(phone):
            return 'Phone Number Incorrect'
        hashed_password = md5.md5(password).hexdigest()
        new_user = {
                'phone':phone,
                'password':hashed_password,
                'openid': str(uuid.uuid4()),
                }
        user_model_obj = UserModel()
        user_model_obj.set(phone,new_user)
        return render_template('register_post.html',error=error)
    return render_template('register.html',error=error)


@app.route('/api/profile/<data>', methods=['GET', 'POST'])
@token_required
def get_profile(current_user):
    """
    returns the users protected profile
    """
    #return jsonify({'current_user':current_user})
    return render_template('profile.html',data=current_user)


@app.route('/api/resource/<data>', methods=['GET', 'POST'])
@token_required
def resource(current_user):
    """
    returns a protected resource
    """
    return jsonify({'resource':'resource'})
    #return render_template('profile.html',data=current_user)


@app.route('/login', methods=['GET', 'POST'])  
def login_user(): 
    """
    logs the user in
    """
    error = None
    if request.method == 'POST':
        password = request.form['password']  
        username = request.form['phone']
        user_model_obj = UserModel()
        user = user_model_obj.get(username)
        if user and verify_password(user['password'], password):
            token = jwt.encode({'phone': user['phone'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
            #return jsonify({'token' : token.decode('UTF-8')})
            return redirect(url_for('get_profile', data=token))
        else:
            error = "Username and/or Password is incorrect"
    return render_template('login.html', error=error)


@app.route('/users', methods=['GET'])
def get_all_users():  
    """
    gets a list of all the registered users
    """
    user_model_obj = UserModel()
    users = user_model_obj.keys()
    result = []   
    user_data = {}
    for user in users:   
        user_data.update({user:user_model_obj.get(user)}) 
    result.append(user_data)   
    return jsonify({'users': result})


def __check_phone_number(phone):
    """
    checks if the users phone number is in the correct format
    """
    phone = str(phone)
    pre = re.compile('^0\d{2,3}\d{7,8}$|^1[23456789]\d{9}$|^147\d{8}')
    phonematch = pre.match(phone) 
    if phonematch:
        return True
    return False


def verify_password(user_pass,password):
    """
    checks if the users password is the same as the one in the database
    """
    password = md5.md5(password).hexdigest()
    if user_pass != password:
        return False
    return True


def verify_auth_token(token):
    """
    checks if the token is still valid
    """
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'])
    except:
        return False
    return UserModel().get(data['phone'])


app.run(host='0.0.0.0',port=8001,debug=True)