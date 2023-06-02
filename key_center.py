import sys
import socket
import selectors
import types
import subprocess
import time
from datetime import datetime


bytes_num = 1024
DATA_UPLOAD_REQ = 0
DATA_DOWNLOAD_REQ = 1
sel = selectors.DefaultSelector()

def accept_wrapper(sock):
    conn, addr = sock.accept()  
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

key_center = {"name":[] , "purpose":[], "keyid" : [], "hash_value" : []}
def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    global payload_max_num
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(bytes_num)  # Should be ready to read
        if recv_data:
            
            total_len = len(recv_data)
            print(recv_data)
            if recv_data[0] == DATA_UPLOAD_REQ:
                print(recv_data)
                # name, purpose, keyid, hash value
                name_size = recv_data[1] 
                print(type(name_size),name_size)
                name = recv_data[2:2+name_size].decode('utf-8').replace("\n","")
                print(name)
                purpose_size = recv_data[2+name_size]
                purpose = recv_data[3+name_size:3+name_size+purpose_size].decode('utf-8').replace("\n","")
                print(purpose,purpose_size)
                
                keyid_size = recv_data[3+name_size+purpose_size]
                keyid = recv_data[4+name_size+purpose_size:4+name_size+purpose_size+keyid_size]
                print(keyid,keyid_size)
                hash_value_size = recv_data[4+name_size+purpose_size+keyid_size]
                hash_value = recv_data[5+name_size+purpose_size+keyid_size:5+name_size+purpose_size+keyid_size+hash_value_size]
                print(hash_value,hash_value_size)

            elif recv_data[1] == DATA_DOWNLOAD_REQ:
                print(recv_data)

        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)

    
port = 22100
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