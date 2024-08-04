import socket
import threading
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password")
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private, pem_public

private_key_pem, public_key_pem = generate_rsa_key_pair()

def encrypt_message(message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message)

def decrypt_message(encrypted_message, key):
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_message)

def handle_client(conn, addr):
    print(f"Client {addr} connected.")
    conn.sendall(public_key_pem) 

    client_key = conn.recv(1024)
    cipher_suite = Fernet(client_key)
    
    clients.append(conn)  
    try:
        while True:
            encrypted_message = conn.recv(1024)
            if not encrypted_message:
                break
            decrypted_message = decrypt_message(encrypted_message, client_key).decode()
            print(f"Received from {addr}: {decrypted_message}")

            for client_conn in clients:
                if client_conn != conn:
                    encrypted_response = encrypt_message(decrypted_message.encode(), client_key)
                    client_conn.sendall(encrypted_response)
    finally:
        clients.remove(conn) 
        conn.close()
        print(f"Client {addr} disconnected.")

def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 65432))
        s.listen()
        print("Server is listening...")
        while True:
            conn, addr = s.accept()
            conn = context.wrap_socket(conn, server_side=True)
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    clients = []
    main()
