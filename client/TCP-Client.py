import socket
import threading
import os
TCP_IP = '192.168.123.126'
TCP_PORT = 10010
BUFFER_SIZE = 2048
TCP_USER_TIMEOUT = 18  # Linux 中的 TCP_USER_TIMEOUT 套接字选项
timeout_value = 2000  # 超时值（毫秒）

def handle_server_response(s):
    while True:
        data = s.recv(BUFFER_SIZE)
        if not data:
            break
        print("Receiving Server Data")
        try:
            message = data.decode('utf-8')
            print(message)
        except UnicodeDecodeError:
            print('Received data is not in a valid text format')

def handle_user_input(s):
    while True:
        user_input = input("Please enter the message you want to send (type 'q' to exit):")
        if user_input.lower() == 'q':
            break
        try:
            s.sendall(user_input.encode())
        except socket.error as e:
            print("Error sending data:", e)
        else:
            print("Msg Data sent successfully")

# 创建socket对象
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_TCP, TCP_USER_TIMEOUT, timeout_value)

# 建立TCP连接
s.connect((TCP_IP, TCP_PORT))

# 发送消息


# 创建一个线程来处理服务器发送的数据
server_thread = threading.Thread(target=handle_server_response, args=(s,))
server_thread.start()

# 创建一个线程来处理用户输入并将其发送给服务器
input_thread = threading.Thread(target=handle_user_input, args=(s,))
input_thread.start()

server_thread.join()
input_thread.join()

s.close()
