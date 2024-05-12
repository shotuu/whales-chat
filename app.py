from flask import Flask, render_template, redirect, url_for, request, escape, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime, timezone
import pytz

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'yayilovewhales!!!!12345'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_admin = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Message {self.username}: {self.message}>'

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@login_required
def index():
    messages = Message.query.order_by(Message.timestamp.desc()).limit(50).all()
    messages.reverse()
    return render_template('index.html', messages=messages)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', form=form, login_error="Invalid username or password")
    return render_template('login.html', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/users")
@login_required
def list_users():
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return "Unauthorized", 403
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route("/edit_user/<int:user_id>", methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin:
        return "Unauthorized", 403
    user = User.query.get_or_404(user_id)
    form = RegistrationForm(obj=user)
    if form.validate_on_submit():
        user.username = form.username.data
        user.set_password(form.password.data)
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('edit_user.html', form=form, user_id=user_id)

@app.route("/delete_user/<int:user_id>", methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "Unauthorized", 403
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/toggle_admin/<int:user_id>")
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        return "Unauthorized", 403
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route("/download_chat_history")
@login_required
def download_chat_history():
    if not current_user.is_admin:
        return "Unauthorized", 403
    messages = Message.query.order_by(Message.timestamp.asc()).all()
    chat_history = "Username,Message,Timestamp\n"
    for message in messages:
        chat_history += f'{message.username},"{message.message}",{message.timestamp}\n'
    return Response(
        chat_history,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=chat_history.csv"})

@app.route("/clear_chat_history", methods=['POST'])
@login_required
def clear_chat_history():
    if not current_user.is_admin:
        return "Unauthorized", 403
    Message.query.delete()
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

def get_utc_now():
    return datetime.now(pytz.utc)

@socketio.on('send_message')
def handle_message(data):
    timestamp = datetime.now(pytz.utc)  # Get current UTC time
    escaped_message = escape(data['message'])
    message = Message(
        username=current_user.username,
        message=escaped_message,
        timestamp=timestamp,
        is_admin=current_user.is_admin
    )
    db.session.add(message)
    db.session.commit()
    emit('receive_message', {
        'username': current_user.username,
        'message': escaped_message,
        'timestamp': timestamp.isoformat(),  # ISO format with 'Z' suffix for UTC
        'is_admin': current_user.is_admin
    }, broadcast=True)

online_users = {}

@socketio.on('connect')
def on_connect(auth=None):
    if current_user.is_authenticated:
        online_users[current_user.username] = request.sid  # Map username to session ID
        emit('user_online', {'username': current_user.username}, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated and current_user.username in online_users:
        online_users.pop(current_user.username, None)
        emit('user_offline', {'username': current_user.username}, broadcast=True)


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()  # Initialize database
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('password1')
            db.session.add(admin_user)
            db.session.commit()
        socketio.run(app, debug=True, host='0.0.0.0')
