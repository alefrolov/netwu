#!/usr/bin/env python3
import sys
import socket
import argparse


def run(sock, pars, address):
    if pars.server:
        sock.bind(address)
        if pars.tcp:
            sock.listen(1)
        try:
            while True:
                if not pars.udp:
                    cl, addr = sock.accept()
                    msg = cl.recv(2048).decode()
                    print('Client connected from using TCP:',
                          addr[0], ':', addr[1])
                    print('Message received:', msg)
                    cl.send(msg.upper().encode())
                    cl.close()
                else:
                    msg, addr = sock.recvfrom(2048)
                    print('Client connected from using UDP:',
                          addr[0], ':', addr[1])
                    msg = msg.decode()
                    print('Message received:', msg)
                    responce = msg.upper().encode()
                    if pars.connect:
                        sock.connect(addr)
                        print('Connected to client:', addr)
                        sock.send(responce)
                    else:
                        sock.sendto(responce,  addr)
        finally:
            sock.close()
    else:
        if not pars.udp or pars.connect:
            sock.connect(address)
            print('Connected to server:', address)
        msg = input('Enter sentense: ')
        if pars.connect:
            sock.send(msg.encode())
        else:
            sock.sendto(msg.encode(), address)
        resp = sock.recv(2048)
        print('Received message: ', resp.decode())
        sock.close()


def parseRawMessage(msg):
    ip_ver = msg[0][0] >> 4
    header_len = msg[0][0] & 0b00001111
    serv_type = msg[0][1]
    dgram_len = int.from_bytes(
        msg[0][2:4], byteorder="big", signed=False)
    dgram_id = int.from_bytes(
        msg[0][5:7], byteorder="big", signed=False)
    reserved_flag0 = msg[0][6] >> 7
    DF_flag = msg[0][6] >> 6
    MF_flag = msg[0][6] >> 5
    offset = msg[0][6] & 0b00011111
    livetime = msg[0][8]
    upper_protocol = msg[0][9]
    checksum = int.from_bytes(msg[0][10:12], byteorder='big')
    ip_source = []
    ip_dest = []
    for i in range(12, 16):
        ip_source.append(msg[0][i])
    for i in range(16, 20):
        ip_dest.append(msg[0][i])
    print('IP Version:', ip_ver)
    print('Header lenght:', header_len)
    print('Service type:', serv_type)
    print('Datagramm lenght', dgram_len)
    print('Datagramm ID:', dgram_id)
    print('Zero flag:', reserved_flag0)
    print('Do not fragment:', DF_flag)
    print('More fragments:', MF_flag)
    print('Offset:', offset)
    print('Livetime:', livetime)
    print('Upper protocol:', upper_protocol)
    print('Checksum', checksum)
    print('Source IP:', end='')
    print(*ip_source, sep='.')
    print('Destenation IP:', end='')
    print(*ip_dest, sep='.')
    payload = msg[0][20:].decode()
    return payload


def rawServer(address):
    try:
        rawSock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        rawSock.bind(address)
        rawSock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
        while True:
            msg = rawSock.recvfrom(4096)
            payload = parseRawMessage(msg)
            print('Received payload:\n'+payload)
            responce = payload.upper()
            rawSock.sendto(responce.encode(), msg[1])

    finally:
        rawSock.close()


def rawClient(address):
    try:
        rawSock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        rawSock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
        message = input("Enter message:")
        rawSock.sendto(message.encode(), address)
        msg = rawSock.recvfrom(4096)
        payload = parseRawMessage(msg)
        print("Responce from server:\n"+payload)
    finally:
        rawSock.close()


def main():
    parser = argparse.ArgumentParser('Parser')
    parser.add_argument("-t", "--tcp", action="store_true")
    parser.add_argument("-s", "--server", action="store_true")
    parser.add_argument("-u", "--udp", action="store_true")
    parser.add_argument("-c", "--connect", action="store_true")
    parser.add_argument("-r", "--raw", action="store_true")
    parser.add_argument("host", type=str)
    parser.add_argument("port", type=int)

    args = parser.parse_args()
    mainSocket = None
    if args.raw:
        try:
            if args.server:
                rawServer((args.host, args.port))
            else:
                rawClient((args.host, args.port))
        except KeyboardInterrupt:
            pass

    else:
        if args.tcp:
            mainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif args.udp:
            mainSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            mainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            run(mainSocket, args, (args.host, args.port))
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
