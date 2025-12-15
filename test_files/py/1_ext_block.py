import subprocess, sys
if len(sys.argv) > 1:
    result = subprocess.run(sys.argv[1], shell=True, capture_output=True, text=True)
    print(result.stdout or result.stderr or '(no output)')
else:
    print("No command")
