#!/usr/bin/env python3

"""
TiTs isn't Telegram, sorry.

This file is a basic implementation of a TiTs server

"""

HOST, PORT = "localhost", 60007
import socketserver
import threading
import time


class MyHandler (socketserver.BaseRequestHandler):
    """
    the message server
    """
    def handle (self):
        client_ip, client_port = self.client_address

        print("ip, port => {} : {}".format(client_ip, client_port))
        cur_thread = threading.current_thread()
        data = self.request.recv(1024)
        while data:
            print("T: {}".format(cur_thread.name))
            print(time.time())
            print(data.decode())
            data = self.request.recv(1024)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


if __name__ == "__main__":
    print("server Runs on {}:{}".format(HOST, PORT))

    server = ThreadedTCPServer((HOST, PORT), MyHandler)


    try:
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.start()
    except KeyboardInterrupt:
        server.shutdown()
        print("server shutdown")
