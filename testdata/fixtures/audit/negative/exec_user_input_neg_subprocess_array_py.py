import subprocess


def list_dir():
    subprocess.run(["ls", "-la"])
