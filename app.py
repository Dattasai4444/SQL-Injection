import re
import logging
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask App
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key in production

# Configure Logging for SQL Injection Detection
logging.basicConfig(
    filename='sql_injection.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

# Setup Database with SQLAlchemy
engine = create_engine('sqlite:///database.db', echo=False)
Base = declarative_base()

class User(UserMixin, Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    password = Column(String(150), nullable=False)  # Hashed passwords

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db_session = Session()

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Loader Callback
@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(int(user_id))

# Helper Function to Detect SQL Injection Patterns
def detect_sql_injection(input_str):
    # Common SQL Injection patterns
    patterns = {
        'Union-based': r'union(\s)+select',
        'Error-based': r'error\s*=\s*\'',
        'Boolean-based': r'\'\s+or\s+\'1\'=\'1',
        'Time-based': r'\'\s+waitfor\s+delay',
        'Inline Comment': r'--',
        'Piggy-backed Query': r';\s*drop\s+table'
    }
    for attack_type, pattern in patterns.items():
        if re.search(pattern, input_str, re.IGNORECASE):
            return attack_type
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Detect SQL Injection Attempts
        attack_type_username = detect_sql_injection(username)
        attack_type_password = detect_sql_injection(password)

        if attack_type_username:
            logging.warning(f"SQL Injection Attempt Detected in Username: {attack_type_username}")
            flash('Invalid input detected.', 'danger')
            return redirect(url_for('login'))

        if attack_type_password:
            logging.warning(f"SQL Injection Attempt Detected in Password: {attack_type_password}")
            flash('Invalid input detected.', 'danger')
            return redirect(url_for('login'))

        # Use Parameterized Queries to Prevent SQL Injection
        user = db_session.query(User).filter(User.username == username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Route to Create a User (For Testing Purposes)
@app.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if db_session.query(User).filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('create_user'))

        # Hash the password before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        new_user = User(username=username, password=hashed_password)
        db_session.add(new_user)
        db_session.commit()
        flash('User created successfully.', 'success')
        return redirect(url_for('login'))

    return render_template('create_user.html')

if __name__ == '__main__':
    app.run(debug=True)
