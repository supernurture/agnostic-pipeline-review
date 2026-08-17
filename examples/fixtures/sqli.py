"""Fixture: risky patterns to bait Semgrep. Do not use any of this as an example."""

import subprocess


def find_user(cursor, name):
    # SQL assembled from input — injection.
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cursor.fetchall()


def ping(host):
    # shell=True with unsanitised input — command injection.
    return subprocess.run("ping -c 1 " + host, shell=True)


def load(payload):
    # eval over data from outside.
    return eval(payload)
