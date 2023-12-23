import socket
import threading
import os
import time
HOST = '0.0.0.0'
PORT = 10010

def handle_client(conn, addr):
    print('Client Connected：', addr)
    while True:
        data = conn.recv(4096)
        if not data:
            print('Client Disconnected')
            break
        print('Receiving Client Data')

        if data[0:11] == b"ECCDONE#&!":
            print("ECCDONE")
            try:
                time.sleep(10)
                conn.sendall(b"ECC1#&!"+os.urandom(669))
            except socket.error as e:
                print("Error sending data:", e)
            else:
                print("ECC KEY Data sent successfully")
        else:
            try:
                message = data.decode('utf-8')
                print(message)
            except UnicodeDecodeError:
                print('Received data is not in a valid text format')

def handle_user_input(conn):
    while True:
        user_input = input("Please enter the message you want to send (type 'q' to exit):")
        if user_input.lower() == 'q':
            break
        try:
            conn.sendall(user_input.encode())
        except socket.error as e:
            print("Error sending data:", e)
        else:
            print("Msg Data sent successfully")


# 创建 TCP 套接字
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print('Waiting for connections...')

    while True:
        conn, addr = s.accept()
        with conn:
            # 创建一个线程来处理客户端发送的数据
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

            # 创建一个线程来处理用户输入并将其发送给客户端
            input_thread = threading.Thread(target=handle_user_input, args=(conn,))
            input_thread.start()

            client_thread.join()
            input_thread.join()

            print("Connection closed")
            break
