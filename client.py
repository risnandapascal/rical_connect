import socket
import ssl
from cryptography.fernet import Fernet

def encrypt_message(message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message)

def decrypt_message(encrypted_message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_message)

def main():
    context = ssl.create_default_context()
    context.load_verify_locations(cafile="server.crt")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s = context.wrap_socket(s, server_hostname='localhost')
        s.connect(('127.0.0.1', 65432))

        public_key_pem = s.recv(1024)

        key = Fernet.generate_key()
        s.sendall(key)

        cipher_suite = Fernet(key)

        while True:
            message = input("You: ")
            encrypted_message = encrypt_message(message.encode(), key)
            s.sendall(encrypted_message)

            encrypted_response = s.recv(1024)
            decrypted_response = decrypt_message(encrypted_response, key).decode()
            print(f"Server: {decrypted_response}")

if __name__ == "__main__":
    main()
