import os
import hashlib
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_from_directory,
    render_template_string,
)

app = Flask(__name__)

# Configure upload folder and allowed extensions
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECRET_KEY"] = "super-secret-key"

db = SQLAlchemy(app)
migrate = Migrate(app, db)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_upload_folder(self):
        # Create a unique string from username and password hash
        unique_string = self.username + self.password_hash
        folder_name = hashlib.sha256(unique_string.encode()).hexdigest()
        return folder_name


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/cabinet")
def cabinet():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    if user:
        upload_folder = os.path.join(
            app.config["UPLOAD_FOLDER"], user.get_upload_folder()
        )
        if os.path.exists(upload_folder):
            files = os.listdir(upload_folder)
        else:
            files = []
        return render_template("cabinet.html", files=files)
    else:
        return redirect(url_for("login"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        user = User.query.filter_by(username=session["username"]).first()
        if user and "document" in request.files:
            file = request.files["document"]
            if file.filename == "":
                return redirect(request.url)
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                upload_folder = os.path.join(
                    app.config["UPLOAD_FOLDER"], user.get_upload_folder()
                )
                os.makedirs(
                    upload_folder, exist_ok=True
                )  # Create the user-specific folder if it doesn't exist
                file.save(os.path.join(upload_folder, filename))
                return redirect(url_for("cabinet"))
    return render_template("upload.html")


@app.route("/download/<filename>")
def download(filename):
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    if user:
        upload_folder = os.path.join(
            app.config["UPLOAD_FOLDER"], user.get_upload_folder()
        )
        return send_from_directory(upload_folder, filename, as_attachment=True)
    else:
        return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if not User.query.filter_by(username=username).first():
            new_user = User(username=username)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            # Create user-specific upload folder
            upload_folder = os.path.join(
                app.config["UPLOAD_FOLDER"], new_user.get_upload_folder()
            )
            os.makedirs(upload_folder, exist_ok=True)
            return redirect(url_for("login"))
        else:
            flash("Username already exists")
    return render_template("register.html")


# Home page
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("cabinet"))
    return render_template("index.html")


# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Store the user's information in the session
            session["username"] = user.username
            return redirect(url_for("cabinet"))
        else:
            flash("Invalid username or password")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)  # Remove the username from the session
    return redirect(url_for("index"))


# Search page (vulnerable to SSTI)
@app.route("/search")
def search():
    if "username" not in session:
        return redirect(url_for("login"))

    user = User.query.filter_by(username=session["username"]).first()
    if user:
        query = request.args.get("query", "")
        upload_folder = os.path.join(
            app.config["UPLOAD_FOLDER"], user.get_upload_folder()
        )
        matching_files = []

        if os.path.exists(upload_folder):
            for filename in os.listdir(upload_folder):
                file_path = os.path.join(upload_folder, filename)
                with open(file_path, "rt", encoding="utf-8", errors="ignore") as file:
                    if query.lower() in file.read().lower():
                        matching_files.append(filename)
        return render_template("search_results.html", files=matching_files, query=query)
    else:
        return redirect(url_for("login"))


if __name__ == "__main__":
    app.run("0.0.0.0", debug=True)
