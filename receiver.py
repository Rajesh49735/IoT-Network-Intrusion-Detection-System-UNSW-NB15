import socket

HOST = "0.0.0.0"
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print("🚀 Waiting for ESP8266 traffic...")

while True:
    conn, addr = server.accept()
    data = conn.recv(1024).decode().strip()

    print("📡 Traffic received:", data)

    conn.close()
