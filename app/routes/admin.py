#!/usr/bin/env python3

from flask import (
    redirect,
    render_template,
    url_for,
    flash,
    request,
)
from flask_login import (
    login_required,
    current_user,
)
from sqlalchemy import desc

from app.routes.forms import (
    AddUser,
    EditUser,
)
from app import app, db, log, models as m


@app.route("/users/", methods=["GET", "POST"])
@login_required
def users():
    form = AddUser()

    if form.validate_on_submit():
        if current_user.role != m.UserRole.ADMIN:
            flash("You are not permitted to add users.", "warning")
            return redirect(url_for("users"))

        try:
            role = m.UserRole[form.role.data.upper()]
        except KeyError:
            flash(f"{form.role.data!r} is not a valid role.", "warning")
            return redirect(url_for("users"))

        user = m.User(
            username=form.username.data,
            password=form.password.data,
            role=role,
            temp_password=True,
            token=m.get_uuid(),
        )

        db.session.add(user)
        db.session.commit()

        flash(f"User {user.username!r} has been added.", "success")
        return redirect(url_for("users"))

    else:

        if current_user.role != m.UserRole.ADMIN:
            flash("You are not permitted to edit users.", "warning")
            return redirect(url_for("dashboard"))

        users = m.User.query.order_by(m.User.id).all()
        return render_template("users.html", form=form, users=users)


@app.route("/users/<user_id>", methods=["GET", "POST"])
@login_required
def user(user_id):
    form = EditUser()

    if form.validate_on_submit():
        if current_user.role != m.UserRole.ADMIN:
            flash("You are not permitted to edit users.", "warning")
            return redirect(url_for("users"))

        try:
            role = m.UserRole[form.role.data.upper()]
        except KeyError:
            flash(f"{form.role.data!r} is not a valid role.", "warning")
            return redirect(url_for("users"))

        user = m.User.query.get_or_404(user_id)
        user.role = role
        db.session.commit()

        flash(f"Changes to {user.username!r} have been made.", "success")
        return redirect(url_for("users"))

    else:

        if current_user.role != m.UserRole.ADMIN:
            flash("You are not permitted to edit users.", "warning")
            return redirect(url_for("dashboard"))

        user = m.User.query.get_or_404(user_id)
        form.role.data = user.role.name.lower()
        return render_template("users.html", form=form, user=user)


@app.route("/users/<user_id>/delete/")
@login_required
def delete_user(user_id):

    name = m.User.query.get_or_404(user_id).username
    m.User.query.filter_by(id=user_id).delete()

    db.session.commit()

    log("info", f"Deleting user: {name!r}")
    flash(f"User {name!r} has been deleted", "success")
    return redirect("users")


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
            m.Log.query.filter_by(level=level.upper())
            .order_by(desc(m.Log.timestamp))
            .limit(limit)
            .all()
        )
    else:
        logs = m.Log.query.order_by(desc(m.Log.timestamp)).limit(limit).all()

    return render_template("logs.html", logs=logs, level=level, limit=limit)
