from flask import Flask, render_template, url_for, redirect, flash, session
from flask_session import Session
#https://www.youtube.com/watch?v=Y4qHNcl4f0Y
from forms import RegistrationForm, LoginForm, contactForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy()
login_manager = LoginManager()

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

app.config['SECRET_KEY'] = '9c76ece7f057069dbe9a222650b8366d054aebda0eba567b8b3afe8194814f92'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"

login_manager.init_app(app)
db.init_app(app)
bcrypt = Bcrypt(app)
Session(app)

# Create user model
class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    def __str__(self):
        return f"{self.username} {self.email}"

with app.app_context():
    db.create_all()

# Creates a user loader callback that returns the user object given an id
@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)

posts = [{
    'author': 'auht1',
    'title': 'titl11',
    'content': 'cont1',
    'date_posted': 'Apr 21,2021'},
    {
        'author': 'auht2',
        'title': 'titl12',
        'content': 'cont2',
        'date_posted': 'Apr 22,2021'},
    {
        'author': 'auht3',
        'title': 'titl13',
        'content': 'cont3',
        'date_posted': 'Apr 23,2021'},
]


@app.route('/home')
@app.route('/', )
def home():
    # check if the users exist or not
    if not session.get("name"):
        # if not there in the session then redirect to the login page
        return redirect(url_for("login"))
    return render_template('home.html', title='home', posts=posts)


@app.route('/about')
def about():
    # check if the users exist or not
    if not session.get("name"):
        # if not there in the session then redirect to the login page
        return redirect(url_for("login"))
    return render_template('about.html', title='about')


@app.route('/contact', methods=['GET', 'POST'])
def contact_us():
    form = contactForm()
    if form.validate_on_submit():
        flash(f"Thanks for contacting us, {form.name.data} Will soon contact you  !", 'success')
        return redirect(url_for('home'))
    return render_template('contact_us.html', title='contact us', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        print(form.username.data)
        print(form.email.data)
        print(form.password.data)
        print(form.email.data)
        user = Users.query.filter_by(email = form.email.data)
        print(user)
        if user is None:
            flash(f"Account {form.email.data} Already exist.", 'failure')
            return render_template('register.html', title='register', form=form)
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        print(hashed_password)
        try:
            user = Users(username=form.username.data, password=hashed_password, email=form.email.data)
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            flash(f"User {form.username.data} could not be created. please try again, Error: {str(e)} !", 'failure')
            return render_template('register.html', title='register', form=form)
        else:
            flash(f"User created successfully {form.username.data} !", 'success')
            return redirect(url_for('login'))
    return render_template('register.html', title='register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is not None:
            print(user.password, form.password.data)
            is_valid = bcrypt.check_password_hash(user.password, form.password.data)

        if user is None:
            flash(f"User {form.email.data} does not exit. please try again. !", 'failure')
            return redirect(url_for("login"))
        elif is_valid :
            login_user(user)
            session['loggedin'] = True
            session['userid'] = user.id
            session['name'] = user.username
            session['email'] = user.email

            message = 'Logged in successfully !'

            flash(f"Welcome {user.username}!", 'success')
            return redirect(url_for("home"))
        else:
            flash(f"Password does not match. please try again. !", 'failure')
            return redirect(url_for("login"))
    return render_template('login.html', title='Login', form=form)

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    return redirect(url_for("login"))

@app.route('/users', methods=['GET', 'POST'])
def all_users():
    users = Users.query.all()
    print(str(users))
    return render_template('all_users.html', title='All Users', users=users)

if __name__ == '__main__':
    app.run(debug=True)

##30 min
# https://www.youtube.com/watch?v=UIJKdCIEXUQ&list=PL-osiE80TeTs4UjLw5MM6OjgkjFeUxCYH&index=3
