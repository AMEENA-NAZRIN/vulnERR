import subprocess

def execute_command(user_input):
    # Validate input to prevent command injection
    if any(char in user_input for char in [';', '&', '|']):
        print("Invalid input. Please enter a valid filename.")
    return

command = ['ls', user_input]
try:
    output = subprocess.check_output(command, stderr=subprocess.STDOUT)
    print(output.decode())
except subprocess.CalledProcessError as e:
    print(f"Command failed with error: {e}")

user_input = input("Enter your command: ")
execute_command(user_input)