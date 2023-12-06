import subprocess

# Define PowerShell commands or scripts
powershell_commands = [
    'python encoderEmulator.py "127.0.0.1" 8000 "00:00:00:00" "00:02:00:00"',
    'python encoderEmulator.py "127.0.0.1" 8001 "00:00:00:00" "00:02:00:00"'
    #Can also be run with real Time, not loops
    #'python encoderEmulator.py "127.0.0.1" 8000 realTime'
    
]

# Loop through each command and run a new PowerShell process
for cmd in powershell_commands:
    subprocess.Popen(['powershell', '-Command', cmd], shell=True)