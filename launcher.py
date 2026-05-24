import os
import sys
import subprocess
import time
import shutil

def get_python_executable():
    pypy = shutil.which("pypy3") or shutil.which("pypy")
    if pypy: return pypy
    return sys.executable

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    script = "main.py"
    if os.path.exists(script):
        try:
            cmd = [get_python_executable(), script] + sys.argv[1:]
            subprocess.run(cmd, check=False)
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(10)
    else:
        print("main.py not found!")
        time.sleep(10)
