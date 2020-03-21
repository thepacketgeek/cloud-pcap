#!/usr/bin/env python3

import os

from flask import (
    redirect,
    render_template,
    url_for,
    flash,
    request,
    send_file,
)
from flask_login import (
    login_required,
    login_user,
    logout_user,
    current_user,
)
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.utils import secure_filename

from app.routes.forms import (
    EditTags,
    LoginForm,
    ProfileForm,
    TempPasswordForm,
)
from app import app, db, log, login_manager, models as m, pcap
from app.routes import api


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_server_error(e):
    log("error", "Exception: %s" % e)
    return render_template("500.html", e=e), 500


@login_manager.user_loader
def load_user(user_id):
    return m.User.query.get(int(user_id))


@app.route("/login/", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = m.User.query.filter_by(username=form.username.data.lower()).first()
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
        user = m.User.query.filter_by(id=current_user.id).one()
        user.temp_password = False
        db.session.commit()

        flash("Password has been changed.", "success")
        return redirect(url_for("home"))

    else:
        tag = request.args.get("tag")
        if tag:
            traceFiles = [
                m.TraceFile.query.filter_by(id=x.file_id).first()
                for x in m.Tag.query.filter_by(name=tag).all()
            ]
        else:
            traceFiles = m.TraceFile.query.all()

        tags = set([x.name for x in m.Tag.query.all()])
        return render_template("home.html", form=form, traceFiles=traceFiles, tags=tags)


@app.route("/profile/", methods=["GET", "POST"])
@login_required
def profile():
    form = ProfileForm()

    if form.validate_on_submit():
        user = m.User.query.filter_by(username=current_user.username).one()
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
        user = m.User.query.filter_by(username=current_user.username).one()
        form.email.data = user.email
        return render_template("profile.html", form=form)


@app.route("/captures/<file_id>")
@login_required
def captures(file_id):
    tagsForm = EditTags(prefix="tags")
    display_filter = request.args.get("display_filter")
    traceFile = m.TraceFile.query.get_or_404(file_id)

    try:
        tagsForm.tags.data = ", ".join(
            x.name for x in m.Tag.query.filter_by(file_id=file_id).all()
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

    tags = set([x.name for x in m.Tag.query.all()])

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
    traceFile = m.TraceFile.query.get_or_404(file_id)
    return pcap.get_packet_detail(traceFile, number), 200


@app.route("/captures/upload")
@login_required
def upload_file():
    api.api_upload_file(current_user.token)
    return redirect(url_for("home"))


@app.route("/captures/delete/<file_id>")
@login_required
def delete_file(file_id):
    api.api_delete_file(current_user.token, file_id)
    return redirect(url_for("home"))


@app.route("/savetags/<file_id>", methods=["POST"])
@login_required
def save_tags(file_id):
    tags = request.data

    # delete tags
    m.Tag.query.filter_by(file_id=file_id).delete()
    # add remaining tags
    for tag in [x.strip() for x in tags.split(",")]:
        if tag != "":
            new_tag = m.Tag(name=secure_filename(tag), file_id=file_id)
            db.session.add(new_tag)

    db.session.commit()

    return "Tags have been updated."


@app.route("/savename/<file_id>", methods=["POST"])
@login_required
def save_name(file_id):
    name = request.data

    if name:
        traceFile = m.TraceFile.query.filter_by(id=file_id).one()
        traceFile.name = secure_filename(name)
        db.session.commit()

    return "Name has been updated."


@app.route("/downloadfile/<file_id>/<attachment_name>")
@login_required
def download_file(file_id, attachment_name):
    traceFile = m.TraceFile.query.get_or_404(file_id)

    return send_file(
        os.path.join(pcap.upload_folder, traceFile.filename),
        attachment_filename=attachment_name,
    )
