#!/usr/bin/env python3

import os
import datetime
import uuid
import base64
import secrets
from enum import Enum
from os.path import splitext

import chartkick
from flask import (
    redirect,
    render_template,
    url_for,
    flash,
    request,
    Flask,
    send_file,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate, MigrateCommand
from flask_login import (
    LoginManager,
    login_required,
    login_user,
    UserMixin,
    logout_user,
    current_user,
)
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from app.config import Config
from app.forms import (
    LoginForm,
    EditTags,
    ProfileForm,
    AddUser,
    EditUser,
    TempPasswordForm,
)
from app.pcap_helper import PcapHelper


app = Flask(__name__)
bootstrap = Bootstrap(app)

app.jinja_env.add_extension("chartkick.ext.charts")
app.config.from_object(Config)

BASE_DIR = os.environ.get("BASE_DIR", "/opt/flask-app")
ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static/tracefiles/")


def format_comma(value):
    return "{:,.0f}".format(value)


app.jinja_env.filters["format_comma"] = format_comma

## db setup
db = SQLAlchemy(app, session_options={"expire_on_commit": False})

pcap = PcapHelper(BASE_DIR)

migrate = Migrate(app, db)
## Login Manager
login_manager = LoginManager(app)
login_manager.session_protection = "strong"
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class UserRole(Enum):
    ADMIN = 0
    USER = 1

    def __str__(self) -> str:
        return self.name


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    token = db.Column(db.String(64))
    role = db.Column(db.Enum(UserRole), default=UserRole.USER)
    temp_password = db.Column(db.Boolean())

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password: set):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User [{self.role}] {self.username!r}>"


class TraceFile(db.Model):
    __tablename__ = "tracefiles"

    id = db.Column(db.String(8), primary_key=True)
    name = db.Column(db.String(128), index=True)
    description = db.Column(db.Text())
    filename = db.Column(db.String(128))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    username = db.relationship("User")
    filesize = db.Column(db.Integer)  # Bytes
    filetype = db.Column(db.String(64))
    packet_count = db.Column(db.Integer)
    date_added = db.Column(db.DateTime)

    def __repr__(self):
        return f"<TraceFile {self.name!r}, filename: {self.filename!r}>"


class Tag(db.Model):
    __tablename__ = "tags"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    file_id = db.Column(db.String(8), db.ForeignKey("tracefiles.id"))

    def __repr__(self):
        return f"<Tag {self.name!r}, file_id: {self.file_id!r}>"


class Log(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime)
    level = db.Column(db.String)  # info, warning, error
    description = db.Column(db.String)

    def __repr__(self):
        return f"<Log [{self.level}]: {self.timestamp} - {self.description}>"


def get_uuid():
    return secrets.token_hex(16)


# Create DB tables and default admin user if they don't exist
def init_db(username="admin", password="cloudpcap"):
    print("Initizializing DB")
    db.create_all()
    admin = User(
        username=username, password=password, role=UserRole.ADMIN, token=get_uuid()
    )
    db.session.add(admin)
    print(f"User {username!r} added with password: {password!r}")
    db.session.commit()


def allowed_file(filename: str) -> bool:
    return "." in filename and (filename.split(".")[-1] in ALLOWED_EXTENSIONS)


def log(level, description):
    note = Log(
        timestamp=datetime.datetime.now(), level=level.upper(), description=description
    )
    db.session.add(note)
    db.session.commit()


@app.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.lower()).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user)
        else:
            flash("Invalid username or password.", "danger")
            return redirect(request.args.get("next") or url_for("login"))

        if user.temp_password:
            return redirect(url_for("home"))
        else:
            return redirect(request.args.get("next") or url_for("home"))

    else:
        return render_template("login.html", form=form)


@app.route("/logout/", methods=["GET", "POST"])
def logout():
    logout_user()
    flash("You have been logged out.", "warning")
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def home():

    form = TempPasswordForm()

    if form.validate_on_submit():

        user = User.query.filter_by(id=current_user.id).one()

        if user.verify_password(form.temp_password.data):
            user.password = form.new_password1.data
        else:
            flash("Current password is not correct.", "danger")
            return redirect(url_for("home"))

        user.temp_password = False
        db.session.commit()

        flash("Password has been changed.", "success")
        return redirect(url_for("home"))

    else:

        tag = request.args.get("tag")

        if tag:
            traceFiles = [
                TraceFile.query.filter_by(id=x.file_id).first()
                for x in Tag.query.filter_by(name=tag).all()
            ]
            # For future use of filtering just one users' files
            # traceFiles = [TraceFile.query.filter_by(user_id=current_user.id).filter_by(id=x.file_id).first() for x in Tag.query.filter_by(name=tag).all()]
        else:
            traceFiles = TraceFile.query.all()
            # For future use of filtering just one users' files
            # traceFiles = TraceFile.query.filter_by(user_id=current_user.id).all()

        tags = set([x.name for x in Tag.query.all()])

        return render_template("home.html", form=form, traceFiles=traceFiles, tags=tags)


@app.route("/captures/<file_id>")
@login_required
def captures(file_id):

    tagsForm = EditTags(prefix="tags")

    display_filter = request.args.get("display_filter")

    traceFile = TraceFile.query.get_or_404(file_id)

    try:
        tagsForm.tags.data = ", ".join(
            x.name for x in Tag.query.filter_by(file_id=file_id).all()
        )
    except NoResultFound:
        tagsForm.tags.data = ""

    display_count, details = pcap.decode_capture_file_summary(traceFile, display_filter)

    if isinstance(details, str):
        flash(details, "warning")
        return render_template(
            "captures.html",
            traceFile=traceFile,
            tagsForm=tagsForm,
            display_count=display_count,
        )

    tags = set([x.name for x in Tag.query.all()])

    return render_template(
        "captures.html",
        traceFile=traceFile,
        tagsForm=tagsForm,
        display_count=display_count,
        details=details,
        tags=tags,
    )


@app.route("/captures/<file_id>/packetDetail/<int:number>")
def packet_detail(file_id: str, number: int):

    traceFile = TraceFile.query.get_or_404(file_id)

    return pcap.get_packet_detail(traceFile, number), 200


@app.route("/users/", methods=["GET", "POST"])
@login_required
def users():
    form = AddUser()

    if form.validate_on_submit():
        if current_user.role != UserRole.ADMIN:
            flash("You are not permitted to add users.", "warning")
            return redirect(url_for("users"))

        try:
            role = UserRole[form.role.data.upper()]
        except KeyError:
            flash(f"{form.role.data!r} is not a valid role.", "warning")
            return redirect(url_for("users"))

        user = User(
            username=form.username.data,
            password=form.password.data,
            role=role,
            temp_password=True,
            token=get_uuid(),
        )

        db.session.add(user)
        db.session.commit()

        flash(f"User {user.username!r} has been added.", "success")
        return redirect(url_for("users"))

    else:

        if current_user.role != UserRole.ADMIN:
            flash("You are not permitted to edit users.", "warning")
            return redirect(url_for("dashboard"))

        users = User.query.order_by(User.id).all()
        return render_template("users.html", form=form, users=users)


@app.route("/users/<user_id>", methods=["GET", "POST"])
@login_required
def user(user_id):
    form = EditUser()

    if form.validate_on_submit():
        if current_user.role != UserRole.ADMIN:
            flash("You are not permitted to edit users.", "warning")
            return redirect(url_for("users"))

        try:
            role = UserRole[form.role.data.upper()]
        except KeyError:
            flash(f"{form.role.data!r} is not a valid role.", "warning")
            return redirect(url_for("users"))

        user = User.query.get_or_404(user_id)
        user.role = role
        db.session.commit()

        flash(f"Changes to {user.username!r} have been made.", "success")
        return redirect(url_for("users"))

    else:

        if current_user.role != UserRole.ADMIN:
            flash("You are not permitted to edit users.", "warning")
            return redirect(url_for("dashboard"))

        user = User.query.get_or_404(user_id)
        form.role.data = user.role.name.lower()
        return render_template("users.html", form=form, user=user)


@app.route("/users/<user_id>/delete/")
@login_required
def delete_user(user_id):

    name = User.query.get_or_404(user_id).username
    User.query.filter_by(id=user_id).delete()

    db.session.commit()

    log("info", f"Deleting user: {name!r}")
    flash(f"User {name!r} has been deleted", "success")
    return redirect("users")


@app.route("/profile/", methods=["GET", "POST"])
@login_required
def profile():

    form = ProfileForm()

    if form.validate_on_submit():

        user = User.query.filter_by(username=current_user.username).one()

        user.email = form.email.data

        if form.new_password1.data:
            if user.verify_password(form.current_password.data):
                user.password = form.new_password1.data
            else:
                db.session.commit()
                flash("Current password is not correct.", "danger")
                return redirect(url_for("profile"))

        db.session.commit()

        flash("Profile changes saved.", "success")
        return redirect(url_for("profile"))

    else:

        user = User.query.filter_by(username=current_user.username).one()

        form.email.data = user.email

        return render_template("profile.html", form=form)


@app.route("/api/v1/<token>/upload", methods=["POST", "PUT"])
def api_upload_file(token):

    try:
        user = User.query.filter_by(token=token).one()
    except NoResultFound:
        return jsonify(exceptions=["API Token is missing or invalid"], status=404)

    if request.method == "POST":
        traceFile = request.files["file"]
        filename = traceFile.filename
        filetype = splitext(filename)[1].strip(".")
        uuid_filename = ".".join([str(uuid.uuid4()), filetype])
        traceFile.save(os.path.join(UPLOAD_FOLDER, uuid_filename))

    else:
        filename = request.args.get("filename")
        filetype = splitext(filename)[1].strip(".")
        uuid_filename = f"{uuid.uuid4()}.{filetype}"
        with open(os.path.join(UPLOAD_FOLDER, uuid_filename), "w") as f:
            f.write(request.stream.read())

    if not allowed_file(filename):
        os.remove(os.path.join(UPLOAD_FOLDER, uuid_filename))
        return jsonify(
            exceptions=["Not a valid file type. (pcap, pcapng, cap)"], status=406
        )

    new_file = TraceFile(
        id=str(uuid.uuid4())[:8],
        name=secure_filename(splitext(filename)[0]),
        user_id=user.id,
        filename=uuid_filename,
        filetype=filetype,
        filesize=os.path.getsize(os.path.join(UPLOAD_FOLDER, uuid_filename)),
        packet_count=pcap.get_capture_count(uuid_filename),
        date_added=datetime.datetime.now(),
    )

    db.session.add(new_file)
    db.session.commit()
    db.session.refresh(new_file)

    # add tags
    if request.form.getlist("additional_tags"):
        for tag in request.form.getlist("additional_tags")[0].split(","):
            if tag.strip(",") != "":
                new_tag = Tag(name=tag.strip(","), file_id=new_file.id)
                db.session.add(new_tag)

    db.session.commit()

    log("info", f"File uploaded by {user.username!r}: {filename!r}.")
    return jsonify(filename=filename, id=new_file.id, status=202)


@app.route("/captures/upload")
@login_required
def upload_file():

    api_upload_file(current_user.token)
    return redirect(url_for("home"))


@app.route("/api/v1/<token>/delete/<file_id>")
def api_delete_file(token, file_id):

    try:
        traceFile = TraceFile.query.filter_by(id=file_id).one()
    except NoResultFound:
        return jsonify(message="Capture not found.", id=file_id, status=404)

    try:
        user = User.query.filter_by(id=traceFile.user_id).one()
    except NoResultFound:
        return jsonify(message="Capture not found.", id=file_id, status=404)

    if token == user.token:
        Tag.query.filter_by(file_id=file_id).delete()
        TraceFile.query.filter_by(id=file_id).delete()

        db.session.commit()
        os.remove(os.path.join(UPLOAD_FOLDER, traceFile.filename))
        log("info", f"File deleted by {user.username!r}: {traceFile.name}.")
        return jsonify(
            message="Capture deleted successfully.", id=traceFile.id, status=200
        )
    else:
        return jsonify(message="Not Authorized.", status=403)


@app.route("/captures/delete/<file_id>")
@login_required
def delete_file(file_id):

    api_delete_file(current_user.token, file_id)

    return redirect(url_for("home"))


@app.route("/savetags/<file_id>", methods=["POST"])
@login_required
def save_tags(file_id):

    tags = request.data

    # delete tags
    Tag.query.filter_by(file_id=file_id).delete()
    # add remaining tags
    for tag in [x.strip() for x in tags.split(",")]:
        if tag != "":
            new_tag = Tag(name=secure_filename(tag), file_id=file_id)
            db.session.add(new_tag)

    db.session.commit()

    return "Tags have been updated."


@app.route("/savename/<file_id>", methods=["POST"])
@login_required
def save_name(file_id):

    name = request.data

    if name:

        traceFile = TraceFile.query.filter_by(id=file_id).one()

        traceFile.name = secure_filename(name)

        db.session.commit()

    return "Name has been updated."


@app.route("/downloadfile/<file_id>/<attachment_name>")
@login_required
def download_file(file_id, attachment_name):

    traceFile = TraceFile.query.get_or_404(file_id)

    return send_file(
        os.path.join(UPLOAD_FOLDER, traceFile.filename),
        attachment_filename=attachment_name,
    )


@app.route("/help/")
@login_required
def help():
    return render_template("help.html")


@app.route("/logs/")
@login_required
def logs():

    level = request.args.get("level")
    limit = request.args.get("limit")

    try:
        limit = int(limit)
    except (ValueError, TypeError):
        limit = 50

    if level:
        logs = (
            Log.query.filter_by(level=level.upper())
            .order_by(desc(Log.timestamp))
            .limit(limit)
            .all()
        )
    else:
        logs = Log.query.order_by(desc(Log.timestamp)).limit(limit).all()

    return render_template("logs.html", logs=logs, level=level, limit=limit)


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    log("error", "Exception: %s" % e)
    return render_template("500.html", e=e), 500


@app.before_first_request
def schedule_updates():
    log("info", "-------------- App has started --------------")


@app.shell_context_processor
def make_shell_context():
    return dict(
        app=app,
        db=db,
        User=User,
        Tag=Tag,
        TraceFile=TraceFile,
        Log=Log,
        init_db=init_db,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, threaded=True)

