import datetime
import hashlib
import io
import logging
import multiprocessing
import os
import socket
import tarfile
import zipfile

from flask import Flask, request, jsonify, make_response, abort, json

from cuckoo.common.config import config
from cuckoo.common.files import Files, Folders
from cuckoo.common.utils import parse_bool, constant_time_compare, parse_options
from cuckoo.core.database import Database, Task
from cuckoo.core.rooter import rooter
from cuckoo.core.submit import SubmitManager
from cuckoo.misc import cwd, version, decide_cwd, Pidfile

log = logging.getLogger(__name__)
db = Database()
sm = SubmitManager()

app = Flask(__name__)


def json_error(status_code, message):
    """Return a JSON object with a HTTP error code."""
    response = jsonify(message=message)
    response.status_code = status_code
    return response


def shutdown_server():
    """Shutdown API werkzeug server."""
    shutdown = request.environ.get("werkzeug.server.shutdown")
    if shutdown:
        shutdown()
        return True
    else:
        return False


@app.after_request
def custom_headers(response):
    """Set some custom headers across all HTTP responses."""
    response.headers["Server"] = "Machete Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@app.route("/tasks/create/file", methods=["POST"])
@app.route("/v1/tasks/create/file", methods=["POST"])
def tasks_create_file():
    data = request.files["file"]
    package = request.form.get("package", "")
    timeout = request.form.get("timeout", "")
    priority = request.form.get("priority", 1)
    options = request.form.get("options", "")
    machine = request.form.get("machine", "")
    platform = request.form.get("platform", "")
    tags = request.form.get("tags")
    custom = request.form.get("custom", "")
    owner = request.form.get("owner", "")
    clock = request.form.get("clock")

    memory = parse_bool(request.form.get("memory", False))
    unique = parse_bool(request.form.get("unique", False))
    enforce_timeout = parse_bool(request.form.get("enforce_timeout", False))

    content = data.read()
    if unique and db.find_sample(sha256=hashlib.sha256(content).hexdigest()):
        return json_error(400, "This file has already been submitted")

    temp_file_path = Files.temp_named_put(content, data.filename)

    task_id = db.add_path(
        file_path=temp_file_path,
        package=package,
        timeout=timeout,
        priority=priority,
        options=options,
        machine=machine,
        platform=platform,
        tags=tags,
        custom=custom,
        owner=owner,
        memory=memory,
        enforce_timeout=enforce_timeout,
        clock=clock
    )

    return jsonify(task_id=task_id)


@app.route("/tasks/create/url", methods=["POST"])
@app.route("/v1/tasks/create/url", methods=["POST"])
def tasks_create_url():
    url = request.form.get("url")
    package = request.form.get("package", "")
    timeout = request.form.get("timeout", "")
    priority = request.form.get("priority", 1)
    options = request.form.get("options", "")
    machine = request.form.get("machine", "")
    platform = request.form.get("platform", "")
    tags = request.form.get("tags")
    custom = request.form.get("custom", "")
    owner = request.form.get("owner", "")

    memory = parse_bool(request.form.get("memory", False))
    enforce_timeout = parse_bool(request.form.get("enforce_timeout", False))
    clock = request.form.get("clock")

    task_id = db.add_url(
        url=url,
        package=package,
        timeout=timeout,
        options=options,
        priority=priority,
        machine=machine,
        platform=platform,
        tags=tags,
        custom=custom,
        owner=owner,
        memory=memory,
        enforce_timeout=enforce_timeout,
        clock=clock
    )

    return jsonify(task_id=task_id)


@app.route("/tasks/create/submit", methods=["POST"])
@app.route("/v1/tasks/create/submit", methods=["POST"])
def tasks_create_submit():
    files = []
    for f in request.files.getlist("file") + request.files.getlist("files"):
        files.append({
            "name": f.filename, "data": f.read(),
        })

    if files:
        submit_type = "files"
    elif request.form.get("strings"):
        submit_type = "strings"
        strings = request.form["strings"].split("\n")
    else:
        return json_error(500, "No files or strings have been given!")

    options = {
        "procmemdump": "yes",
        **parse_options(request.form.get("options", ""))
    }

    submit_id = sm.pre(
        submit_type, files or strings, sm.translate_options_to(options)
    )
    if not submit_id:
        return json_error(500, "Error creating Submit entry")

    files, errors, options = sm.get_files(submit_id, astree=True)

    options["full-memory-dump"] = parse_bool(
        request.form.get("memory", config("cuckoo:cuckoo:memory_dump"))
    )
    options["enforce-timeout"] = parse_bool(
        request.form.get("enforce_timeout", False)
    )

    def selected(files, arcname=None):
        ret = []
        for entry in files:
            if entry.get("selected"):
                entry["arcname"] = arcname
                ret.append(entry)
            ret += selected(entry["children"], arcname or entry["filename"])
        return ret

    task_ids = sm.submit(submit_id, {
        "global": {
            "timeout": request.form.get("timeout", ""),
            "priority": request.form.get("priority", 1),
            "tags": request.form.get("tags"),
            "custom": request.form.get("custom", ""),
            "owner": request.form.get("owner", ""),
            "clock": request.form.get("clock"),
            "options": options,
        },
        "file_selection": selected(files),
    })
    return jsonify(submit_id=submit_id, task_ids=task_ids, errors=errors)


# Implement other routes and functions similarly

if __name__ == "__main__":
    from cuckoo.core.startup import ensure_tmpdir, init_console_logging

    decide_cwd(exists=True)
    db.connect()
    init_console_logging()
    ensure_tmpdir()

    if os.environ.get("CUCKOO_APP") == "api":
        hostname = config("cuckoo:cuckoo:api_host")
        port = config("cuckoo:cuckoo:api_port")
        debug = config("cuckoo:cuckoo:api_debug")
        cuckoo_api(hostname, port, debug)
