import subprocess

def run_unsafe():
    user_input = input("Enter shell command: ")
    subprocess.call(user_input, shell=True)  # command injection

def hardcoded_secret():
    password = "supersecret"  # hardcoded credential
