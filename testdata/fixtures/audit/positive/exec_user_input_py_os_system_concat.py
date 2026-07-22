import os

def run_listing(user_dir):
    # os.system building a shell string via concatenation
    os.system("ls " + user_dir)
