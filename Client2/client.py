import socket
import sys
import ssl
import pprint
import datetime
from threading import Thread
import select

eve_flag = False


def user_info(user_id):
    if user_id == "1":
        user = " [You]"
    if user_id == "2":
        user = " [Server]"
    currentTime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sp_char = "\r"
    sys.stdout.write(sp_char + currentTime + user + ": ")
    sys.stdout.flush()


def send_msg(ssl_s):
    global eve_flag
    while not eve_flag:
        read_sock, write_sock, error_sock = select.select([], [ssl_s], [])
        for sock in write_sock:
            if sock == ssl_s:
                data = sys.stdin.readline()
                if data == "exit\n":
                    eve_flag = True
                    ssl_s.send(data.encode())
                    return
                else:
                    ssl_s.send(data.encode())
                    user_info("1")


def rcv_msg(ssl_s):
    global eve_flag
    while not eve_flag:
        read_sock, write_sock, error_sock = select.select([ssl_s], [], [])
        for sock in read_sock:
            if sock == ssl_s:
                data = ssl_s.recv(4096).decode()
                if not data:
                    print("\r[Error]: Disconnected From Server")
                    eve_flag = True
                    break
                else:
                    if data[:7] == "Client<":
                        user_info("2")
                        sys.stdout.write(data)
                        sys.stdout.flush()
                        user_info("1")
                    else:
                        sys.stdout.write(data)
                        sys.stdout.flush()
                        user_info("1")
    return


if __name__ == "__main__":

    if len(sys.argv) < 3:
        print("Usage: python3 client.py [hostname] [port]")
        sys.exit()

    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    ip_port = (HOST, PORT)

    # ssl.PROTOCOL_TLS对应客户端和服务器均支持的最高协议版本
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # 验证对方证书
    context.verify_mode = ssl.CERT_REQUIRED
    # 加载验证服务器证书的CA证书
    context.load_verify_locations("ca.crt")
    # 加载一个私钥及对应的证书
    context.load_cert_chain(certfile="client.crt", keyfile="client.key")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = context.wrap_socket(s, server_hostname='127.0.0.1')

    try:
        s.connect(ip_port)
    except:
        print("\r[Error]: Failed to Connect the Server")
        sys.exit()

    # 格式化输出证书信息
    print("-----------------------------------------------------------------")
    print("[Info]: Server's Certificate")
    print("-----------------------------------------------------------------")
    pprint.pprint(s.getpeercert())
    print("-----------------------------------------------------------------")
    print("[Info]: Successfully Connected to Server. Able to Send Messages")
    print("-----------------------------------------------------------------")
    
    user_info("1")
    send_thread = Thread(target=send_msg, args=(s, ))
    rcv_thread = Thread(target=rcv_msg, args=(s, ))
    send_thread.daemon = True
    rcv_thread.daemon = True

    send_thread.start()
    rcv_thread.start()


    while not eve_flag:
        continue
    sys.exit()
    s.close()
