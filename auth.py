from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash("Tous les champs sont requis.", "error")
            return redirect(url_for("auth.register"))

        if User.query.filter_by(username=username).first():
            flash("Ce nom d'utilisateur est déjà utilisé.", "error")
            return redirect(url_for("auth.register"))

        hashed = generate_password_hash(password)
        user = User(username=username, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        flash("Inscription réussie. Vous pouvez vous connecter.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Nom d'utilisateur ou mot de passe incorrect.", "error")
            return redirect(url_for("auth.login"))

        session["user_id"] = user.id
        session["username"] = user.username  
        flash("Connexion réussie.", "success")
        return redirect(url_for("index"))

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    flash("Vous êtes déconnecté.", "info")
    return redirect(url_for("auth.login"))
