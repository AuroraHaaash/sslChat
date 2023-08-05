import socket
import select
import ssl
from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import DES
import datetime


def pre_info():
    currentTime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sp_char = "\r"
    return sp_char + currentTime 


def broadcast_data(s, msg):
    for socket_item in con_list:
        if socket_item != server_socket and socket_item != s:
            try:
                socket_item.write(msg.encode())
            except:
                socket_item.close()
                con_list.remove(socket_item)


def save_msg(msg):
    msg = msg + (8 - len(msg) % 8) * ' '
    c_msg = des_ob.encrypt(msg.encode())
    pass_hex = b2a_hex(c_msg)

    fp = open('ChatRecord', 'a')
    fp.write(pass_hex.decode())
    fp.close()


if __name__ == "__main__":
    con_list = []
    IP = '127.0.0.1'
    PORT = 9999
    ip_port = (IP, PORT)

    key = '12345678'.encode()
    des_ob = DES.new(key, DES.MODE_ECB)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 调用close(socket)后,仍可继续重用该socket。调用close(socket)一般不会立即关闭socket，而经历TIME_WAIT的过程。
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(ip_port)
    server_socket.listen(2)

    con_list.append(server_socket)

    # ssl.PROTOCOL_TLS对应客户端和服务器均支持的最高协议版本
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    # 验证对方证书
    context.verify_mode = ssl.CERT_REQUIRED
    # 加载一组用于验证其他对等方证书的CA证书
    context.load_verify_locations("ca.crt")
    # 加载一个私钥及对应的证书
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    print("[Info]: sslChat Server Started On Port-" + str(PORT))

    while True:
        read_sock, write_sock, error_sock = select.select(con_list, [], [])
        for sock in read_sock:
            if sock == server_socket:
                sock_fd, addr = server_socket.accept()
                sock_ssl = context.wrap_socket(sock_fd, server_side=True)
                con_list.append(sock_ssl)
                print("[Info]: Client[%s, %s] Online" % addr)
                broadcast_data(sock_ssl, "Client<%s:%s> Online\n" % addr)
                save_msg(pre_info() + " [Server]: Client<%s:%s> Online\n" % addr)
                # print(addr)
            else:
                data = sock.recv(4096).decode()
                if data:
                    message = pre_info() + " [Client<" + str(sock.getpeername()[0]) + ":" + str(sock.getpeername()[1]) + ">]: " + data
                    broadcast_data(sock, message)
                    save_msg(message)
                else:
                    broadcast_data(sock, "Client<%s, %s> Offline\n" % (sock.getpeername()[0], sock.getpeername()[1]))
                    print("[Info]: Client[%s, %s] Offline" % (sock.getpeername()[0], sock.getpeername()[1]))
                    save_msg(pre_info() + " [Server]: Client<%s:%s> Offline\n" % (sock.getpeername()[0], sock.getpeername()[1]))
                    sock.close()
                    con_list.remove(sock)
                    continue

    server_socket.close()
