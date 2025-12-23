# appp.py (Complete Fixed and Organized File)

from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.orm import joinedload
import os 

# ===============================================
# SOCKETIO IMPORT HANDLING (Standard Setup)
# ===============================================
try:
    import importlib
    socketio_module = importlib.import_module('flask_socketio')
    SocketIO = socketio_module.SocketIO
    emit = socketio_module.emit
    join_room = socketio_module.join_room
except Exception:
    def emit(*args, **kwargs): pass
    def join_room(*args, **kwargs): pass
    class SocketIO:
        def __init__(self, app=None, **kwargs): pass
        def on(self, event): return lambda f: f
        def run(self, app, debug=False): app.run(debug=debug)


app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lawlink.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_super_secret_key_change_me' 

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

socketio = SocketIO(app)

# ===============================================
# MODELS (Database Structures)
# ===============================================
class Lawyer(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    specialty = db.Column(db.String(100), nullable=False)
    contact_number = db.Column(db.String(20), nullable=True) 
    chamber_address = db.Column(db.String(255), nullable=True) 
    profile_image_url = db.Column(db.String(255), nullable=True)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room = db.Column(db.Integer, nullable=False) 
    sender_id = db.Column(db.String(100), nullable=False) 
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_edited = db.Column(db.Boolean, default=False) 
    reactions = db.relationship('Reaction', backref='message', lazy=True, cascade="all, delete-orphan")

class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emoji = db.Column(db.String(10), nullable=False)
    reactor_id = db.Column(db.String(100), nullable=False)
    message_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=False) 

# ===============================================
# FLASK-LOGIN & UTILS
# ===============================================

@login_manager.user_loader
def load_user(user_id):
    return Lawyer.query.get(int(user_id))

def create_tables():
    db.create_all()

def process_reactions(message):
    reaction_counts = {}
    for r in message.reactions:
        reaction_counts[r.emoji] = reaction_counts.get(r.emoji, 0) + 1
    return reaction_counts

# ===============================================
# ROUTES (HTTP Endpoints)
# ===============================================

@app.route('/')
def lawyer_list():
    lawyers = Lawyer.query.all()
    # Check client session to prevent redirect loop
    if 'client_name' in session and 'lawyer_id' in session:
        if Lawyer.query.get(session['lawyer_id']):
            return redirect(url_for('chat', lawyer_id=session['lawyer_id']))
        else:
            session.pop('client_name', None)
            session.pop('lawyer_id', None)
            
    return render_template('lawyers.html', lawyers=lawyers) 

@app.route('/register', methods=['GET', 'POST'])
def register_lawyer():
    if current_user.is_authenticated:
        return redirect(url_for('lawyer_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        specialty = request.form.get('specialty')
        contact_number = request.form.get('contact_number')
        chamber_address = request.form.get('chamber_address')
        profile_image_url = request.form.get('profile_image_url')
        
        existing_lawyer = Lawyer.query.filter_by(email=email).first()
        if existing_lawyer:
            flash('That email is already registered. Please login.', 'danger')
            return redirect(url_for('register_lawyer'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_lawyer = Lawyer(
            name=name, email=email, password=hashed_password, specialty=specialty,
            contact_number=contact_number, chamber_address=chamber_address,
            profile_image_url=profile_image_url
        )

        db.session.add(new_lawyer)
        db.session.commit()

        flash(f'Registration successful! Welcome, {name}. You can now log in.', 'success')
        return redirect(url_for('login')) 

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('lawyer_dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False 

        lawyer = Lawyer.query.filter_by(email=email).first()

        if lawyer and check_password_hash(lawyer.password, password):
            login_user(lawyer, remember=remember) 
            flash('Login successful!', 'success')
            return redirect(url_for('lawyer_dashboard'))
        else:
            flash('Login failed. Check your email and password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required 
def logout():
    logout_user()
    session.pop('client_name', None)
    session.pop('lawyer_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('lawyer_list'))

@app.route('/dashboard')
@login_required 
def lawyer_dashboard():
    lawyer_id = current_user.id
    messages_query = Message.query.options(joinedload(Message.reactions))
    messages = messages_query.filter_by(room=lawyer_id).order_by(Message.timestamp).all()
    
    messages_data = [
        {
            'message': msg, 
            'reactions': process_reactions(msg)
        } for msg in messages
    ]
    return render_template('dashboard.html', lawyer=current_user, messages_data=messages_data)

@app.route('/dashboard/edit_profile', methods=['GET', 'POST'])
@login_required 
def edit_profile():
    if request.method == 'POST':
        current_user.name = request.form.get('name')
        current_user.specialty = request.form.get('specialty')
        current_user.contact_number = request.form.get('contact_number')
        current_user.chamber_address = request.form.get('chamber_address')
        current_user.profile_image_url = request.form.get('profile_image_url')
        
        try:
            db.session.commit()
            flash('Your profile has been updated successfully!', 'success')
            return redirect(url_for('lawyer_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating your profile: {e}', 'danger')
            return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', lawyer=current_user)

# --- FIXED: Delete Account Route ---
# MOVED to correct ROUTES section
@app.route('/dashboard/delete_account', methods=['POST'])
@login_required
def delete_account():
    lawyer_id = current_user.id
    
    # 1. Delete all chat data (Messages and Reactions) associated with this room/lawyer
    Message.query.filter_by(room=lawyer_id).delete()
    
    # 2. Delete the lawyer account
    lawyer_to_delete = Lawyer.query.get_or_404(lawyer_id)
    db.session.delete(lawyer_to_delete)
    
    # 3. Commit changes and log out
    db.session.commit()
    logout_user() 

    flash('Your account and all associated chat data have been permanently deleted.', 'success')
    return redirect(url_for('lawyer_list'))

# ⭐ FIXED: Clears Client Session Route - The ENDPOINT is 'clear_client_session' ⭐
@app.route('/client_logout')
def clear_client_session():
    # Clear client-specific session variables to fix the redirect loop
    session.pop('client_name', None)
    session.pop('lawyer_id', None)
    flash('You have left the chat.', 'info')
    
    return redirect(url_for('lawyer_list'))


@app.route('/chat/start/<int:lawyer_id>', methods=['GET', 'POST'])
def start_chat(lawyer_id):
    if 'client_name' in session and session.get('lawyer_id') == lawyer_id:
         return redirect(url_for('chat', lawyer_id=lawyer_id))

    lawyer = Lawyer.query.get_or_404(lawyer_id)
    
    if request.method == 'POST':
        client_name = request.form.get('client_name')
        if client_name and client_name.strip():
            session['client_name'] = client_name.strip()
            session['lawyer_id'] = lawyer_id
            return redirect(url_for('chat', lawyer_id=lawyer_id))
        else:
            flash('Please enter your name to start the chat.', 'warning')
            
    return render_template('client_name_entry.html', lawyer=lawyer)


@app.route('/chat/<int:lawyer_id>')
def chat(lawyer_id):
    if 'client_name' not in session or session.get('lawyer_id') != lawyer_id:
        return redirect(url_for('start_chat', lawyer_id=lawyer_id))

    lawyer = Lawyer.query.get_or_404(lawyer_id)
    room_id = lawyer_id
    client_name = session['client_name']
    
    messages_query = Message.query.options(joinedload(Message.reactions))
    messages = messages_query.filter_by(room=room_id).order_by(Message.timestamp).all()
    
    messages_data = [
        {
            'message': msg, 
            'reactions': process_reactions(msg)
        } for msg in messages
    ]
    
    return render_template('chat.html', 
                           lawyer=lawyer, 
                           room_id=room_id, 
                           messages_data=messages_data,
                           client_name=client_name)


# ===============================================
# SOCKETIO EVENT HANDLERS
# ===============================================
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)

@socketio.on('message')
def handle_message(data):
    room = data['room']
    msg = data['msg']
    sender = data.get('sender', 'Anonymous Client')
    
    new_message = Message(room=room, sender_id=sender, content=msg)
    db.session.add(new_message)
    db.session.commit()
    
    message_id = new_message.id 

    emit('new_message', {
        'msg': msg,
        'sender': sender,
        'room': room,
        'id': message_id,
        'reactions': {}, 
        'timestamp': datetime.now().strftime('%H:%M')
    }, room=room)

# --- FIXED: Delete Message Handler ---
@socketio.on('delete_message')
def handle_delete_message(data):
    message_id = data.get('id')
    room = data.get('room')
    
    if not message_id or not room:
        return

    message_to_delete = Message.query.get(int(message_id))

    if message_to_delete and message_to_delete.room == int(room):
        db.session.delete(message_to_delete)
        db.session.commit()
        
        emit('message_deleted', {'id': message_id}, room=room)

# --- FIXED: Delete Conversation Handler ---
@socketio.on('delete_conversation')
def handle_delete_conversation(data):
    room = data.get('room')
    if not room:
        return
    
    Message.query.filter_by(room=room).delete()
    db.session.commit()
    
    if 'client_name' in session:
        session.pop('client_name', None)
        session.pop('lawyer_id', None)
    
    emit('conversation_cleared', {'room': room}, room=room)

@socketio.on('edit_message')
def handle_edit_message(data):
    message_id = data.get('id')
    new_content = data.get('content')
    room = data.get('room')
    
    if not message_id or not new_content or not room:
        return

    message_to_edit = Message.query.get(int(message_id))

    if message_to_edit and message_to_edit.room == int(room):
        message_to_edit.content = new_content
        message_to_edit.is_edited = True
        db.session.commit()
        
        emit('message_edited', {
            'id': message_id,
            'content': new_content,
            'is_edited': True
        }, room=room)

@socketio.on('react_to_message')
def handle_reaction(data):
    message_id = data.get('message_id')
    emoji = data.get('emoji')
    sender_name = data.get('sender')
    room = data.get('room')
    
    if not message_id or not emoji or not sender_name or not room:
        return

    existing_reaction = Reaction.query.filter_by(
        message_id=message_id, 
        reactor_id=sender_name
    ).first()

    if existing_reaction:
        if existing_reaction.emoji == emoji:
            db.session.delete(existing_reaction)
        else:
            existing_reaction.emoji = emoji
    else:
        new_reaction = Reaction(
            message_id=message_id, 
            emoji=emoji, 
            reactor_id=sender_name
        )
        db.session.add(new_reaction)
    
    db.session.commit()

    updated_message = Message.query.options(joinedload(Message.reactions)).get(message_id)

    emit('reaction_updated', {
        'message_id': message_id,
        'reactions': process_reactions(updated_message)
    }, room=room)

@socketio.on('typing_start')
def handle_typing_start(data):
    room = data['room']
    sender = data['sender']
    emit('typing_indicator', {'sender': sender, 'is_typing': True}, room=room, include_self=False)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    room = data['room']
    sender = data['sender']
    emit('typing_indicator', {'sender': sender, 'is_typing': False}, room=room, include_self=False)


# ===============================================
# APP EXECUTION
# ===============================================

if __name__ == '__main__':
    socketio.run(app, debug=True, port=8080)