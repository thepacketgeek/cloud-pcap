#!/usr/bin/env python3

""" Script to be run at Docker build time to ensure a random SECRET_KEY for
    Flask is generated and will remain sticky through future container runs
"""

import random
import string
from jinja2 import Environment, BaseLoader

CONFIG_TEMPLATE = """
#!/bin/usr/env python3


class Config:
    SECRET_KEY = "{{ secret_key }}"
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:postgrespswd@db:5432/cloud_pcap"
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False

"""


def generate_secret(length: int) -> str:
    return "".join(
        random.choice(string.ascii_letters + string.digits) for n in range(length)
    )


if __name__ == "__main__":
    template = Environment(loader=BaseLoader).from_string(CONFIG_TEMPLATE)

    output = template.render(secret_key=generate_secret(32))
    with open("app/config.py", "w") as config_file:
        config_file.write(output)
