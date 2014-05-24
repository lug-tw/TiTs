#!/usr/bin/env python3

"""
TiTs isn't Telegram, sorry.

This file is a basic implementation of a TiTs client

"""

HOST, PORT = "localhost", 60007
import socket
import random
import time

class s_client:
    """
    the socket client object
    """
    def __init__(self):
        # message socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.connect((HOST, PORT))

    def send(self, msg=""):
        self.sock.send(msg.encode())
        print("[-]: send: {}".format(msg))

    def __del__(self):
        self.sock.close()

c = s_client()
data  = "o" * random.randint(1, 10)
while 1:
    c.send(str(time.time()) + data)
    time.sleep(0.1)
