import socket

client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_sock.connect(('127.0.0.1', 65432))
client_sock.sendall(b'curl -X GET "localhost:65432/users" -H "Accept: application/json"')
data = client_sock.recv(1024)
client_sock.close()
print('Received', repr(data))