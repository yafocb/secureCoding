# webshell.py
import subprocess
import sys

if len(sys.argv) > 1:
    cmd = sys.argv[1]
    try:
        result = subprocess.run(
            cmd.split(),  # "ls -la" → ["ls", "-la"]
            capture_output=True,
            text=True,
            timeout=5
        )
        print(result.stdout if result.stdout else result.stderr)
    except Exception as e:
        print(f"Error: {e}")
else:
    print("No command provided")