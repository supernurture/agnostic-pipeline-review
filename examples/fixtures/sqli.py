"""Fixture: pola rawan untuk memancing Semgrep. Jangan dipakai sebagai contoh."""

import subprocess


def find_user(cursor, name):
    # SQL dirangkai dari input — injeksi.
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cursor.fetchall()


def ping(host):
    # shell=True dengan input tak tersanitasi — command injection.
    return subprocess.run("ping -c 1 " + host, shell=True)


def load(payload):
    # eval atas data dari luar.
    return eval(payload)
