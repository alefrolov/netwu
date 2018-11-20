#!/usr/bin/env python3
import sys
import socket
import argparse
import logging

def run(sock, pars, address):
    log = logging.getLogger("netwu.Run")
    if pars.server:
        sock.bind(address)
        log.info('Server is listening now: '+address[0]+':'+str(address[1]))
        if pars.tcp:
            sock.listen(1)
        try:
            while True:
                if not pars.udp:
                    cl, addr = sock.accept()
                    log.info('Client connected from using TCP: '+
                          addr[0]+ ':'+ str(addr[1]))
                    msg = cl.recv(2048).decode()
                    #print('Client connected from using TCP:' +
                    #     addr[0] + ':'+ str(addr[1]))
                    log.info('Message received: ' + msg)
                    #print('Message received:', msg)
                    cl.send(msg.upper().encode())
                    log.info('Message sent to '+cl.getsockname()[0]+':'+str(cl.getsockname()[1])+': '+msg.upper())
                    cl.close()
                else:
                    msg, addr = sock.recvfrom(2048)
                    #print('Client connected from using UDP:',
                    #      addr[0], ':', addr[1])
                    log.info('Client connected from using UDP: '+
                          addr[0] + ':' + str(addr[1]))
                    msg = msg.decode()
                    log.info('Message received: '+ msg)
                    #print('Message received:', msg)
                    responce = msg.upper().encode()
                    if pars.connect:
                        sock.connect(addr)
                        log.info('UDP server connected to client ' + addr[0] + str(addr[1]))
                        #print('Connected to client:', addr)
                        sock.send(responce)
                        log.info('Message sent to '+addr[0]+':'+str(addr[1])+': '+ responce)
                    else:
                        sock.sendto(responce,  addr)
                        log.info('Message sent to '+addr[0]+':'+str(addr[1])+': '+ responce.decode())
        finally:
            sock.close()
            log.info("Server finished")
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
    log = logging.getLogger("netwu.RawServer")
    try:
        rawSock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        rawSock.bind(address)
        log.info("Server is listening "+ address[0])
        rawSock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 0)
        while True:
            msg = rawSock.recvfrom(4096)
            payload = parseRawMessage(msg)
            log.info("Server received message: "+payload)
            #print('Received payload:\n'+payload)
            responce = payload.upper()
            rawSock.sendto(responce.encode(), msg[1])
            log.info('Server sent responce: '+responce)

    finally:
        rawSock.close()
        log.info('Server finished')



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
    parser.add_argument("-f", "--filename", dest="filename",type=str)
    parser.add_argument("-o","--stdout", action="store_true")
    parser.add_argument("host", type=str)
    parser.add_argument("port", type=int)

    args = parser.parse_args()
    mainSocket = None


    logger = logging.getLogger("netwu")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if not (args.filename is None):
        filehandler=logging.FileHandler(args.filename)
        filehandler.setFormatter(formatter)
        logger.addHandler(filehandler)
    if args.stdout:
       stdouthandler = logging.StreamHandler(sys.stdout)
       stdouthandler.setFormatter(formatter)
       logger.addHandler(stdouthandler)
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
