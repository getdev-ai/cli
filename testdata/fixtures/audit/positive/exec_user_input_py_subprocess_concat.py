import subprocess

def run_listing(user_dir):
    # subprocess with shell=True + concatenated command string
    subprocess.run("ls " + user_dir, shell=True)
