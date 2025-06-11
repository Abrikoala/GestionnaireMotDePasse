from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from models import db, Password, ShareLink
from auth import auth_bp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from dotenv import load_dotenv
import os, secrets, datetime

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
app.register_blueprint(auth_bp)

AES_KEY = os.environ.get("AES_KEY")
if not AES_KEY or len(AES_KEY.encode()) != 32:
    raise RuntimeError("AES_KEY doit être une chaîne de 32 octets dans le fichier .env")
AES_KEY = AES_KEY.encode()

def encrypt_aes256(plain_text: str) -> bytes:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain_text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted

def decrypt_aes256(cipher_text: bytes) -> str:
    iv = cipher_text[:16]
    encrypted = cipher_text[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    passwords = Password.query.filter_by(user_id=session["user_id"]).all()
    return render_template("index.html", passwords=passwords)

@app.route("/add", methods=["POST"])
def add():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    label = request.form['label']
    username = request.form['username']
    password_plain = request.form['password']
    category = request.form['category']
    encrypted = encrypt_aes256(password_plain)
    new_pass = Password(
        label=label,
        username=username,
        password_encrypted=encrypted,
        category=category,
        user_id=session["user_id"]
    )
    db.session.add(new_pass)
    db.session.commit()
    flash("Mot de passe ajouté !")
    return redirect(url_for("index"))

@app.route("/delete/<int:id>")
def delete(id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    entry = Password.query.get_or_404(id)
    if entry.user_id != session["user_id"]:
        flash("Accès refusé.")
        return redirect(url_for("index"))

    db.session.delete(entry)
    db.session.commit()
    flash("Mot de passe supprimé.")
    return redirect(url_for("index"))

@app.route("/generate")
def generate():
    import random, string
    length = int(request.args.get("length", 16))
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choices(characters, k=length))
    return jsonify(password=password)

@app.route("/reveal/<int:id>")
def reveal(id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    entry = Password.query.get_or_404(id)
    if entry.user_id != session["user_id"]:
        return jsonify(error="Accès non autorisé."), 403

    decrypted = decrypt_aes256(entry.password_encrypted)
    return jsonify(password=decrypted)

@app.route("/share/<int:id>")
def share(id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    entry = Password.query.get_or_404(id)
    if entry.user_id != session["user_id"]:
        return jsonify(error="Accès non autorisé."), 403

    token = secrets.token_urlsafe(16)
    expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    link = ShareLink(password_id=id, token=token, expiration=expiration)
    db.session.add(link)
    db.session.commit()

    url = url_for("shared", token=token, _external=True)
    return jsonify(share_url=url)

@app.route("/shared/<token>")
def shared(token):
    link = ShareLink.query.filter_by(token=token).first_or_404()
    if datetime.datetime.utcnow() > link.expiration:
        flash("Lien expiré.")
        return redirect(url_for("index"))

    entry = Password.query.get_or_404(link.password_id)
    decrypted = decrypt_aes256(entry.password_encrypted)
    return render_template("shared.html", label=entry.label, username=entry.username, password=decrypted)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
