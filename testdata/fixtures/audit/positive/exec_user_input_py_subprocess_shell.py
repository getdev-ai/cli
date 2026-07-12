import subprocess


def run_command(cmd):
    subprocess.call(cmd, shell=True)
