from flask import Flask, jsonify, request
import firebase_admin
from firebase_admin import credentials, firestore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64, uuid, random, smtplib
from email.mime.text import MIMEText
import json
import os


cred_dict = json.loads(os.environ['GOOGLE_APPLICATION_CREDENTIALS_JSON'])
cred = credentials.Certificate(cred_dict)
firebase_admin.initialize_app(cred)
db = firestore.client()




app = Flask(__name__)




@app.route('/register', methods=['POST'])
def register_user():
    try:
        name = request.json.get("name")
        gmail = request.json.get("gmail")

        if not name or not gmail:
            return jsonify({"error": "Name and Gmail are required"}), 400
        
        user_ref = db.collection("Connect_user").document(name)
        user_doc = user_ref.get()


        if user_doc.exists:
            return jsonify({"error": "User exists use a different Name"}), 400

        otp = generate_otp()
        user_ref.set({
            "name": name,
            "gmail": gmail.strip().lower(),
            "otp": otp,
            "verified": False
        })

        send_email(gmail, otp)

        return jsonify({"message": "OTP sent to Gmail"}), 200
        

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({"error": "Internal server error", "message": str(e)}), 500
def generate_otp():
    return str(random.randint(100000, 999999))


def send_email(receiver_email, otp):
    sender_email = "mansinner666@gmail.com"
    sender_password = "jfuaihaslyggigsl"
    subject = "Verification OTP Code"
    body = f"Your OTP is: {otp}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 587) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
    except Exception as e:
        print("Email send failed:", str(e))

@app.route('/verify', methods=['POST'])
def verify_otp():
    try:
        name = request.json.get("name")
        gmail = request.json.get("gmail")
        otp = request.json.get("otp")

        temp_ref = db.collection("Connect_user").document(name)
        temp_doc = temp_ref.get()

        if not temp_doc.exists:
            return jsonify({"error": "No such user pending verification"}), 404

        data = temp_doc.to_dict()

        if data["otp"] != otp or data["gmail"] != gmail:
            temp_ref.delete()
            return jsonify({"error": "Invalid OTP or email"}), 400
        newpass=otp
        user_ref = db.collection("Connect_user").document(name)
        user_ref.update({
        "status":   1,
        "password": otp,
        "otp":      firestore.DELETE_FIELD
        })
        return jsonify({"message": "User verified and registered"}), 200

    except Exception as e:
        print("Error in verify:", str(e))
        return jsonify({"error": "Internal server error", "message": str(e)}), 500

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    name = data.get("name")
    pwd = data.get("otp")

    user_ref = db.collection("Connect_user").document(name)
    doc = user_ref.get()
    if not doc.exists:
        return jsonify({"error": "User not found"}), 404
    record = doc.to_dict()
    if record.get("password") != pwd:
        return jsonify({"error": "Invalid credentials"}), 400
    return jsonify({"message": "Sign-in successful"}), 200

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    try:
        name = request.json.get("name")
        gmail = request.json.get("gmail")

        
        user_ref = db.collection("Connect_user").document(name)
        doc = user_ref.get()

        if not doc.exists:
            return jsonify({"error": "No such user found"}), 404

        user = doc.to_dict()
        if user.get("gmail", "").strip().lower() != gmail.strip().lower():
            return jsonify({"error": "Email does not match registered account"}), 400


       
        otp = str(random.randint(100000, 999999))
        user_ref.update({"otp": otp, "status": 2})

    
        send_email(gmail, otp)

        return jsonify({"message": "Password reset OTP sent to your Gmail"}), 200

    except Exception as e:
        print("Error in forgot_password:", str(e))
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        name = request.json.get("name")
        gmail = request.json.get("gmail")
        otp = request.json.get("otp")
        new_password = request.json.get("new_password")

        user_ref = db.collection("Connect_user").document(name)
        doc = user_ref.get()

        if not doc.exists:
            return jsonify({"error": "No such user found"}), 404

        data = doc.to_dict()

        if data.get("gmail", "").strip().lower() != gmail.strip().lower():
            return jsonify({"error": "Email does not match registered account"}), 400


        if data.get("otp") != otp:
            return jsonify({"error": "Invalid OTP"}), 400

        user_ref.update({
            "password": new_password,
            "status": 1,
            "otp": firestore.DELETE_FIELD,
            "verified": True
        })

        return jsonify({"message": "Password reset successful"}), 200

    except Exception as e:
        print("Error in reset_password:", str(e))
        return jsonify({"error": "Internal server error", "message": str(e)}), 500


@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    data = request.get_json()
    sender = data['sender']
    receiver = data['receiver']

    if sender == receiver:
        return jsonify({"error": "Cannot send request to yourself"}), 400


    sender_ref = db.collection(sender).document(receiver)
    receiver_ref = db.collection(receiver).document(sender)

    if sender_ref.get().exists or receiver_ref.get().exists:
        return jsonify({"error": "Request or friendship already exists"}), 400


    sender_ref.set({
        "sender": sender,
        "receiver": receiver,
        "status": -1
    })
    receiver_ref.set({
        "sender": sender,
        "receiver": receiver,
        "status": 0
    })

    return jsonify({"message": "Friend request sent"}), 200

@app.route('/respond_request', methods=['POST'])
def respond_request():
    try:
        data = request.get_json()
        sender = data['sender']
        receiver = data['receiver']
        status = data.get('status')

        sender_doc = db.collection("Connect_user").document(sender)
        receiver_doc = db.collection("Connect_user").document(receiver)

        if status == 1:
            
            db.collection(receiver).document(sender).update({"status": 1})
            db.collection(sender).document(receiver).update({"status": 1})

       
            for user_a, user_b in [(sender, receiver), (receiver, sender)]:
                user_ref = db.collection("Connect_user").document(user_a)
                user_snapshot = user_ref.get()

                if user_snapshot.exists:
                    data = user_snapshot.to_dict()
                    friends = data.get("friends", [])
                    if user_b not in friends:
                        friends.append(user_b)
                        user_ref.update({"friends": friends})
                else:
                    # Create the user doc if missing
                    user_ref.set({
                        "name": user_a,
                        "friends": [user_b],
                        "online": False
                    }, merge=True)

            return jsonify({"message": "Friend request accepted"}), 200

        else:
       
            db.collection(receiver).document(sender).delete()
            db.collection(sender).document(receiver).delete()
            return jsonify({"message": "Friend request denied"}), 200

    except Exception as e:
        print("Error in respond_request:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/get_friends', methods=['GET'])
def get_friends():
    user = request.args.get("name")
    friends = []
    for doc in db.collection(user).where("status","==",1).stream():
        data = doc.to_dict()
        friends.append(data["receiver"] if data["sender"]==user else data["sender"])
    return jsonify(friends),200

@app.route('/get_suggestions', methods=['GET'])
def get_suggestions():
    try:
        name = request.args.get('name')
        if not name:
            return jsonify({"error": "Missing name"}), 400

 
        all_users = [u.id for u in db.collection("Connect_user").stream()]
        excluded = {name}

        user_doc = db.collection("Connect_user").document(name).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            excluded.update(user_data.get("friends", []))

 
        for doc in db.collection(name).stream():
            d = doc.to_dict()
            other = d.get("receiver") or d.get("sender")
            excluded.add(other)

   
        for other_user in all_users:
            if other_user == name:
                continue
            rel_doc = db.collection(other_user).document(name).get()
            if rel_doc.exists:
                excluded.add(other_user)


        available = [u for u in all_users if u not in excluded]

        import random
        suggestions = random.sample(available, min(5, len(available)))

        return jsonify(suggestions), 200
    except Exception as e:
        print("Error in get_suggestions:", e)
        return jsonify({"error": str(e)}), 500

@app.route('/get_requests', methods=['GET'])
def get_requests():
    user = request.args.get("name")
    query = db.collection(user).where("status", "==", 0)
    docs = query.stream()
    result = [doc.to_dict()["sender"] for doc in docs]
    return jsonify(result), 200

def encrypt_message(plain_text):
    key = b"CphS2dXaGKwVE13oMqYfLBJTR7ztUn60"
    iv = b"zXwRQ7TpYVeNcKj1"
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain_text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

@app.route('/send_message', methods=['POST'])
def send_message():
    try:
        data = request.get_json()
        sender, receiver, message = data.get('sender'), data.get('receiver'), data.get('message')
        if not sender or not receiver or message is None:
            return jsonify({"error": "Missing sender, receiver, or message"}), 400

        enc_msg = encrypt_message(message)
        msg_entry = {"sender": sender, "message": enc_msg, "timestamp": firestore.SERVER_TIMESTAMP}
        db.collection(sender).document(receiver).collection("messages").add(msg_entry)
        db.collection(receiver).document(sender).collection("messages").add(msg_entry)
        return jsonify({"success": True}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_messages', methods=['GET'])
def get_messages():
    try:
        name = request.args.get('name')
        friend = request.args.get('from')
        if not name or not friend:
            return jsonify({"error": "Missing user or friend"}), 400

        messages_ref = db.collection(name).document(friend).collection("messages").order_by("timestamp")
        messages = [m.to_dict() for m in messages_ref.stream()]
        return jsonify(messages), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/set_status', methods=['POST'])
def set_status():
    data = request.json
    name = data.get("name")
    online = data.get("online")
    db.collection("Connect_user").document(name).update({
        "online": online,
        "last_seen": firestore.SERVER_TIMESTAMP if not online else None
    })
    return jsonify({"status": "updated"}), 200

@app.route('/get_statuses', methods=['POST'])
def get_statuses():
    data = request.json
    friends = data.get("friends", [])
    statuses = {}
    for f in friends:
        doc = db.collection("Connect_user").document(f).get()
        if doc.exists:
            d = doc.to_dict()
            statuses[f] = {
                "online": d.get("online", False),
                "last_seen": d.get("last_seen", None)
            }
    return jsonify(statuses), 200

@app.route('/send_file', methods=['POST'])
def send_file():
    try:
        sender_address = request.form.get("sender")
        receiver_address = request.form.get("receiver")
        file_huff = request.files.get("huff_file")
        file_tree = request.files.get("tree_file")

        if not sender_address or not receiver_address or not file_huff or not file_tree:
            return jsonify({"error": "Missing data"}), 400

        filename_base = file_huff.filename.replace(".huff", "")
        file_huff_data = base64.b64encode(file_huff.read()).decode()
        file_tree_data = base64.b64encode(file_tree.read()).decode()
        file_id = str(uuid.uuid4())

        file_entry = {
            "original_filename": filename_base,
            "file_id": file_id,
            "huff_data": file_huff_data,
            "tree_data": file_tree_data,
            "sender": sender_address,
            "receiver": receiver_address,
            "uploaded_at": firestore.SERVER_TIMESTAMP
        }

        for user_a, user_b in [(sender_address, receiver_address), (receiver_address, sender_address)]:
            db.collection(user_a).document(user_b).collection("files").document(file_id).set(file_entry)

        validation_tag = "73942758324"
        msg = f"{filename_base} {file_id} {validation_tag}"
        enc = encrypt_message(msg)
        message = {"sender": sender_address, "message": enc, "timestamp": firestore.SERVER_TIMESTAMP}

        for user_a, user_b in [(sender_address, receiver_address), (receiver_address, sender_address)]:
            db.collection(user_a).document(user_b).collection("messages").add(message)

        return jsonify({"message": "Files sent successfully", "file_id": file_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_files', methods=['POST'])
def get_files():
    try:
        receiver = request.json.get("receiver")
        sender = request.json.get("sender")
        file_id = request.json.get("file_id")
        ref = db.collection(receiver).document(sender).collection("files").document(file_id)
        doc = ref.get()
        if not doc.exists:
            return jsonify({"error": "File not found"}), 404
        return jsonify(doc.to_dict()), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/')
def index():
    return "Piyush's API "

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))



