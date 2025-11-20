from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import os
from urllib.parse import quote_plus
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_fallback_secret_key_for_local_dev') # Use environment variable
# Database configuration using environment variables
DB_USER = os.environ.get('DB_USER')
DB_PASSWORD = os.environ.get('DB_PASSWORD')
DB_HOST = os.environ.get('DB_HOST')
DB_PORT = os.environ.get('DB_PORT', '3306') # Default MySQL port
DB_NAME = os.environ.get('DB_NAME')

if DB_USER and DB_PASSWORD and DB_HOST and DB_NAME:
    encoded_password = quote_plus(DB_PASSWORD)
    app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+mysqlconnector://{DB_USER}:{encoded_password}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
else:
    # Fallback for local development or error if env vars are not set
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///instance/contacts.db" # Or another local database
    print("WARNING: Database environment variables not set. Using SQLite fallback.")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/tours')
def tours():
    return render_template('tours.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists.', 'error')
            return redirect(url_for('register'))

        # Create new user
        new_user = User(
            email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256'),
            is_admin=False  # Default new users are not admins
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Your account has been created! You are now able to log in.', 'message')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Logged in successfully.', 'message')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'message')
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        full_name = request.form['full_name']
        phone_number = request.form['phone_number']

        # Validate phone number
        if phone_number and not re.match(r'^\d{10}$', phone_number):
            flash('Invalid phone number. Please enter exactly 10 digits.', 'error')
            return redirect(url_for('profile'))
        
        current_user.full_name = full_name
        current_user.phone_number = phone_number
        db.session.commit()
        print("Flashing success message: Profile updated successfully!") # Debugging line
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    return render_template('admin.html')

@app.route('/admin/customers')
@login_required
def admin_customers():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin_customers.html', users=users)

@app.route('/admin/customers/<int:user_id>')
@login_required
def admin_customer_details(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_customers'))
    return render_template('admin_customer_details.html', user=user)

@app.route('/admin/customers/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_customer_edit(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    user = db.session.get(User, user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin_customers'))

    if request.method == 'POST':
        user.full_name = request.form['full_name']
        user.phone_number = request.form['phone_number']
        user.is_admin = 'is_admin' in request.form

        password = request.form['password']
        if password:
            user.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Validate phone number
        if user.phone_number and not re.match(r'^\d{10}$', user.phone_number):
            flash('Invalid phone number. Please enter exactly 10 digits.', 'error')
            return redirect(url_for('admin_customer_edit', user_id=user.id))

        db.session.commit()
        flash('Customer details updated successfully!', 'success')
        return redirect(url_for('admin_customer_details', user_id=user.id))

    return render_template('admin_customer_edit.html', user=user)


@app.route('/admin/enquiries')
@login_required
def admin_enquiries():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    enquiries = Contact.query.order_by(Contact.timestamp.desc()).all()
    return render_template('admin_enquiries.html', enquiries=enquiries)

@app.route('/admin/enquiries/<int:enquiry_id>')
@login_required
def admin_enquiry_details(enquiry_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))
    enquiry = db.session.get(Contact, enquiry_id)
    if not enquiry:
        flash('Enquiry not found.', 'error')
        return redirect(url_for('admin_enquiries'))
    return render_template('admin_enquiry_details.html', enquiry=enquiry)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        subject = request.form['subject']
        message = request.form['message']

        # Validations
        if not (2 <= len(name) <= 50):
            flash('Name must be between 2 and 50 characters.', 'error')
            return redirect(request.referrer or url_for('home'))

        if not re.match(r'^\d{10}$', phone):
            flash('Invalid phone number. Please enter 10 digits.', 'error')
            return redirect(request.referrer or url_for('home'))

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Invalid email address.', 'error')
            return redirect(request.referrer or url_for('home'))

        new_contact = Contact(name=name, email=email, phone=phone, subject=subject, message=message)
        db.session.add(new_contact)
        db.session.commit()
        
        flash('Your request has been sent successfully! We will get back to you soon.')
        return redirect(url_for('home'))
        
    return render_template('contact.html')

if __name__ == '__main__':
    import os
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', 5000))
    
    app.run(host=host, port=port, debug=True)
