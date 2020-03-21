#!/usr/bin/env python3

import datetime
import os
import uuid

from flask import request, jsonify
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.utils import secure_filename

from app import app, db, log, models as m, pcap

ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}


def allowed_file(filename: str) -> bool:
    return "." in filename and (filename.split(".")[-1] in ALLOWED_EXTENSIONS)


@app.route("/api/v1/<token>/upload", methods=["POST", "PUT"])
def api_upload_file(token):
    try:
        user = m.User.query.filter_by(token=token).one()
    except NoResultFound:
        return jsonify(exceptions=["API Token is missing or invalid"], status=404)

    if request.method == "POST":
        traceFile = request.files["file"]
        filename = traceFile.filename
        filetype = os.path.splitext(filename)[1].strip(".")
        uuid_filename = ".".join([str(uuid.uuid4()), filetype])
        traceFile.save(os.path.join(pcap.upload_folder, uuid_filename))

    else:
        filename = request.args.get("filename")
        filetype = os.path.splitext(filename)[1].strip(".")
        uuid_filename = f"{uuid.uuid4()}.{filetype}"
        with open(os.path.join(pcap.upload_folder, uuid_filename), "w") as f:
            f.write(request.stream.read())

    if not allowed_file(filename):
        os.remove(os.path.join(pcap.upload_folder, uuid_filename))
        return jsonify(
            exceptions=["Not a valid file type. (pcap, pcapng, cap)"], status=406
        )

    new_file = m.TraceFile(
        id=str(uuid.uuid4())[:8],
        name=secure_filename(os.path.splitext(filename)[0]),
        user_id=user.id,
        filename=uuid_filename,
        filetype=filetype,
        filesize=os.path.getsize(os.path.join(pcap.upload_folder, uuid_filename)),
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
                new_tag = m.Tag(name=tag.strip(","), file_id=new_file.id)
                db.session.add(new_tag)

    db.session.commit()

    log("info", f"File uploaded by {user.username!r}: {filename!r}.")
    return jsonify(filename=filename, id=new_file.id, status=202)


@app.route("/api/v1/<token>/delete/<file_id>")
def api_delete_file(token, file_id):
    try:
        traceFile = m.TraceFile.query.filter_by(id=file_id).one()
    except NoResultFound:
        return jsonify(message="Capture not found.", id=file_id, status=404)

    try:
        user = m.User.query.filter_by(id=traceFile.user_id).one()
    except NoResultFound:
        return jsonify(message="Capture not found.", id=file_id, status=404)

    if token == user.token:
        m.Tag.query.filter_by(file_id=file_id).delete()
        m.TraceFile.query.filter_by(id=file_id).delete()

        db.session.commit()
        os.remove(os.path.join(pcap.upload_folder, traceFile.filename))
        log("info", f"File deleted by {user.username!r}: {traceFile.name}.")
        return jsonify(
            message="Capture deleted successfully.", id=traceFile.id, status=200
        )
    else:
        return jsonify(message="Not Authorized.", status=403)
