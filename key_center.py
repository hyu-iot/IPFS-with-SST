import sys
import socket
import selectors
import types
import subprocess
import time
from datetime import datetime
import psutil


sel = selectors.DefaultSelector()

def accept_wrapper(sock):
    conn, addr = sock.accept()  
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    global payload_max_num
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(bytes_num)  # Should be ready to read
        if recv_data:
            total_len = len(recv_data)
            print(recv_data)
        else:
            print(f"Closing connection to {data.addr}")
            for i,j in enumerate(client_list["sock"]):
                if j == sock:
                    del client_list["data"][i], client_list["id"][i], client_list["sock"][i]
            print(client_list["id"])
            sel.unregister(sock)

    
port = 7001
host, port = '127.0.0.1', port

lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    lsock.close()
    sel.close()
    print("Finished")