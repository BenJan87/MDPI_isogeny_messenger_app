from flask import Flask, redirect, url_for, request, flash, render_template, session, jsonify, abort
from pymongo import MongoClient
from flask_socketio import SocketIO, emit
from functools import wraps
from werkzeug.utils import secure_filename
from bson import ObjectId
import os
import configparser
import hashlib
import datetime
import uuid
import random
import ast

MAX_FILE_SIZE = 512 * 1024  

config = configparser.ConfigParser()
config.read(os.path.abspath(os.path.join('.ini')))

app = Flask(__name__, template_folder='templates')
app.secret_key = config['PROD']['SECRET_KEY']
uri = config['PROD']['DB_URI']
upload_location = config['PROD']['UPLOAD_FOLDER']
db_name = config['PROD']['DB_NAME']

socketio = SocketIO(app)

client = MongoClient(uri)
db = client[db_name]

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    else:
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('register'))

@app.route('/validation', methods=['POST'])
def validation():
    if request.method == 'POST':
        users = db.users
        email = request.form["email"].strip()
        username = request.form["username"].strip()
        passwd = request.form["password"]
        user = users.find_one({'email': email})
        uname = users.find_one({'username': username})

        if len(email) == 0 or len(username) == 0 or len(passwd) == 0: 
            return redirect(url_for("register"))
        if user:
            return redirect(url_for("register"))
        if uname:
            return redirect(url_for("register"))
        else:
            return jsonify(
                {
                "success": True
                }
            ), 200


@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form["email"].strip()
        username = request.form["username"].strip()
        password = request.form["password"]
        IK = request.form["IK"]
        SPK = request.form["SPK"]
        SIGNATURE = request.form["SIGNATURE"]
        BS = request.form["BS"]
        OPKS = request.form["OPKS"]
        SIGN = request.form["SIGN"]
        users = db.users

        try:
            new_user = {
                "username": username,
                "email": email,
                "password": hashlib.sha512(password.encode()).hexdigest(),
                "IK": IK,
                "SPK": SPK,
                "SIGNATURE": SIGNATURE,
                "BS": BS,
                "OPKS": OPKS,
                "SIGN": SIGN,
                "date": datetime.datetime.now()
            }
            users.insert_one(new_user)
            return jsonify({"success": True})
        except:
            flash("Error creating user. Please try again.")
            return jsonify({"success": False})
        
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]
        users = db.users
        user = users.find_one({'email': email})

        if user and user['password'] == hashlib.sha512(password.encode()).hexdigest():
            session['username'] = user['username']
            session['email'] = user['email']
            session['user_id'] = str(user['_id'])
            return redirect(url_for('chat'))
        else:
            flash("Invalid authentication data")
    return render_template("login.html")

@app.route('/upload_public_key', methods=['POST'])
@login_required
def upload_public_key():
    data = request.json
    email = session['email']
    public_key = data['public_key']
    db.users.update_one({'email': email}, {'$set': {'public_key': public_key}})
    return jsonify({'status': 'success'})

@app.route('/get_public_key/<id>', methods=['GET'])
@login_required
def get_public_key(id):
    user = db.users.find_one({'_id': ObjectId(id)})
    if user and 'SPK' in user:
        return jsonify({'public_key': user['SPK']})
    return jsonify({'error': 'Public key not found'}), 404

@app.route('/chat/', methods=['GET', 'POST'])
@login_required
def chat():
    room_id = request.args.get('r', None)
    info = []
    chats = db.chats
    users = db.users
    messages = db.messages
    user_id = session['user_id']
    sender_id = user_id
    chat_recipient_username = None
    has_active_chats = False
    recipient_id = None
    email = users.find_one({'_id': ObjectId(user_id)})['email']
    my_username = users.find_one({'_id': ObjectId(user_id)})['username']
    hash = users.find_one({'_id': ObjectId(user_id)})['password']
    current_recipient_id = None

    try:
        chat_list = chats.find({'participants': user_id})
    except:
        chat_list = []
    
    if chat_list:
        has_active_chats = True
    for chat in chat_list:
        if chat['participants'][0] == user_id:
            recipient_id = chat['participants'][1]
        else:
            recipient_id = chat['participants'][0]
        recipient = users.find_one({'_id': ObjectId(recipient_id)})
        username = recipient['username'] if recipient else 'Unknown'
        recipient_id = str(recipient['_id'])
        recipient_IK = recipient["IK"]
        recipient_SPK = recipient["SPK"]
        recipient_SIGNATURE = recipient["SIGNATURE"]
        recipient_BS = recipient["BS"]
        recipient_OPKS = recipient["OPKS"] 
        ephemeral = chat["ephemeral"]
        host = chat["host"]
        chosen_OPK = chat["chosen_opk"]
        guess = chat["guess"]

        current = False
        if room_id == chat['room_id']:
            current = True
            chat_recipient_username = username
            current_recipient_id = recipient_id
        last_msg = messages.find_one({'room_id': chat['room_id'], 'sender_id': {'$ne': user_id}}, sort=[('timestamp', -1)])
        if not last_msg:
            last_msg = {"message": "No messages yet", "timestamp": ""}
        info.append({
            "username": username,
            "room_id": chat['room_id'],
            "user_id": user_id,
            "current": current,
            "recipient_IK": recipient_IK,
            "recipient_SPK": recipient_SPK,
            "recipient_SIGNATURE": recipient_SIGNATURE,
            "recipient_BS": recipient_BS,
            "chosen_OPK": chosen_OPK,
            "guess": guess,
            "ephemeral": ephemeral,
            "host": host,
            "last_message": {
                "message": last_msg['message'],  
                "timestamp": str(last_msg['timestamp'].strftime("%Y-%m-%d %H:%M")) if last_msg['timestamp'] != "" else None 
            },
            "recipient_id": recipient_id
        })
    return render_template(
        "chat.html",
        room_id=room_id,
        info=info,
        email=email,
        recipient_id=recipient_id,
        sender_id=sender_id,
        user_id=user_id,
        my_username=my_username,
        hash=hash,
        chat_recipient_username=chat_recipient_username,
        room_selected=bool(room_id),
        has_active_chats=has_active_chats,
        current_recipient_id=current_recipient_id
    )

@app.route('/join-chat', methods=['GET', 'POST'])
@login_required
def join_chat():
    users = db.users
    chats = db.chats
    user_id = session['user_id']

    if request.method == 'POST':
        recipient_email = request.form.get('email').strip()
        if recipient_email == session['email']:
            flash("You cannot join a chat with yourself.")
            return redirect(url_for('join_chat'))

        recipient = users.find_one({'email': recipient_email})
    
        if not recipient:
            flash("No user found with that email address.")
            return redirect(url_for('join_chat'))

        recipient_id = str(recipient['_id'])

        existing_chat = chats.find_one({
            'participants': {
                '$all': [user_id, recipient_id]
            }
        })

        if existing_chat:
            flash("You are already in a chat with this user.")
            return redirect(url_for('chat', r=existing_chat['room_id']))

        recipient_SPK = recipient["SPK"]
        recipient_SIGNATURE = recipient["SIGNATURE"]
        recipient_BS = recipient["BS"]
        recipient_SIGN = recipient["SIGN"]
        email = users.find_one({'_id': ObjectId(user_id)})['email']

        info = {
            "EMAIL": email,
            "recipient_SIGN": recipient_SIGN,
            "recipient_SPK": recipient_SPK,
            "recipient_SIGNATURE": recipient_SIGNATURE,
            "recipient_BS": recipient_BS
        }

        return jsonify({'info': info})

    return render_template('join-chat.html')

@app.route('/join-chat-confirm', methods=['POST'])
@login_required
def join_chat_confirm():
    users = db.users
    chats = db.chats
    user_id = session['user_id']

    recipient_email = request.form.get('email', '').strip()
    ephemeral = request.form.get('ephemeral')
    recipient = users.find_one({'email': recipient_email})


    recipient_id = str(recipient['_id'])
    recipient = users.find_one({'_id': ObjectId(recipient_id)})
    recipient_OPKS = recipient["OPKS"]
    recipient_OPKS = list(ast.literal_eval(recipient_OPKS))
    guess = random.randint(0, len(recipient_OPKS)-1)
    chosen_OPK = str(recipient_OPKS[guess])

    new_chat = {
        "room_id": uuid.uuid4().hex,
        "participants": [user_id, recipient_id],
        "host": user_id,
        "creation_date": datetime.datetime.now(),
        "ephemeral": ephemeral,
        "chosen_opk": chosen_OPK,
        "guess": guess
    }
    chats.insert_one(new_chat)

    return jsonify({
        'message': "You have successfully joined the chat.",
        'redirect_url': url_for('chat', r=new_chat['room_id'])
    })

@app.route('/fetch_messages/<room_id>', methods=['GET'])
@login_required
def fetch_messages(room_id):
    user_id = session['user_id']
    messages = db.messages.find({
        'room_id': room_id,
        'sender_id': {"$ne": user_id}
    }).sort('timestamp', 1)
    message_list = []

    for message in messages:
        message_list.append({
            'message': message['message'],
            'header': message['header'],
            'sender_username': message['sender_username'],
            'timestamp': message['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
            'attachment': message.get('attachment', False),
            'filename': message.get('filename', ''),
            'url': message.get('url', '')
        })
    
    return {'messages': message_list}

@app.route('/delete_read_messages', methods=['POST'])
@login_required
def delete_read_messages():
    data = request.get_json()
    room_id = data.get('room_id')
    current_user_id = session.get('user_id')
    result = db.messages.delete_many({
        'room_id': room_id,
        'sender_id': {'$ne': current_user_id} 
    })
    return jsonify({"deleted_count": result.deleted_count})

@app.route('/upload_attachment', methods=['POST'])
@login_required
def upload_attachment():
    messages = db.messages
    filename = request.form.get('filename')
    blob = request.form.get('blob')
    message_text = request.form.get('message', '') 
    header = request.form.get('header') 
    room_id = request.form.get('room_id')

    if not room_id:
        return jsonify({"success": False, "message": "Invalid room."})

    if not filename:
        return jsonify({"success": False, "message": "No file uploaded."})

    if not os.path.exists(upload_location):
        os.makedirs(upload_location)

    original_filename = secure_filename(filename)
    random_filename = uuid.uuid4().hex + "_" + original_filename
    filepath = os.path.abspath(os.path.join(upload_location, random_filename))

    with open(filepath, 'w') as f:
        f.write(blob)

    attachment_message = {
        "room_id": room_id,
        "sender_id": session['user_id'],
        "sender_username": session['username'],
        "message": message_text,  
        "header": header,
        "filename": original_filename,
        "attachment": 1,
        "url": random_filename,
        "timestamp": datetime.datetime.now()
    }

    messages.insert_one(attachment_message)

    socketio.emit('receive_message', {
        'room_id': room_id,
        'sender_id': session['user_id'],
        'sender_username': session['username'],
        'message': message_text,
        'header': header,
        'timestamp': attachment_message['timestamp'].strftime('%Y-%m-%d %H:%M'),
        'attachment': 1,
        'filename': original_filename,
        'url': random_filename,
    })
    
    return jsonify({
                    "success": True,
                    "url": random_filename
                    })


@app.route('/download_attachment/<filename>', methods=['GET'])
@login_required
def download_attachment(filename):
    filepath = os.path.abspath(os.path.join(upload_location, filename))
    blob = None
    try:
        with open(filepath, "r") as f:
            blob = f.read()
        return blob, 200, {
            'Content-Type': 'application/octet-stream', 
            'Content-Disposition': f'attachment'  
        }
    except FileNotFoundError:
        return abort(404, description="File not found.")

@socketio.on('send_message')
def handle_send_message(data):
    room_id = data['room_id']
    message_text = data['message']
    sender_id = session['user_id']
    sender_username = session['username']
    header = data["header"]
    timestamp = datetime.datetime.now()

    new_message = {
        "room_id": room_id,
        "sender_id": sender_id,
        "sender_username": sender_username,
        "message": message_text,
        "header": header,
        "timestamp": timestamp
    }
    db.messages.insert_one(new_message)

    emit('receive_message', {
        'room_id': room_id,
        'message': message_text,
        'sender_username': sender_username,
        'sender_id': sender_id,
        'timestamp': timestamp.strftime('%Y-%m-%d %H:%M')
    })

if __name__ == '__main__':
    socketio.run(app)
