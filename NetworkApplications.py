#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
from distutils.file_util import write_file
import ipaddress
import socket
import select
import os
import sys
import struct
import time
from turtle import delay


def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=Proxy, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, time_sent, timeout):
        # 1. Wait for the socket to receive a reply
        timeLeft = timeout
        while True:
            started_select = time.time()
            ready = select.select([icmpSocket], [], [], timeLeft)
            how_long_in_select = time.time() - started_select

            if ready[0] == []:  # Timeout
                return

        # 2. Once received, record time of receipt, otherwise, handle a timeout
            time_received = time.time()

            received_packet, addr = icmpSocket.recvfrom(1024)
            received_header = received_packet[20:28]

            type, code, checksum, p_id, sequence = struct.unpack('bbHHh', received_header)

            if p_id == ID:
                return time_received - time_sent
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        # 4. Unpack the packet header for useful information, including the ID
        # 5. Check that the ID matches between the request and reply
        # 6. Return total network delay
        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        ipAddress = socket.gethostbyname(destinationAddress)
        # 1. Build ICMP header
        header = struct.pack("bbHHh", 8, 0, 0, ID, 1)
        # 2. Checksum ICMP packet using given function
        check = NetworkApplication.checksum(self, header)
        # 3. Insert checksum into packet
        header = struct.pack("bbHHh", 8, 0, check, ID, 1)
        # 4. Send packet using socket
        icmpSocket.sendto(header, (ipAddress, 1))
        # 5. Record time of sending
        return time.time()
        pass

    def doOnePing(self, destinationAddress, timeout):
        icmpSocket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_ICMP
        )

        time_sent = self.sendOnePing(icmpSocket, destinationAddress, 1)
        
        total_delay = self.receiveOnePing(icmpSocket, destinationAddress, 1, time_sent, timeout=1)
        
        icmpSocket.close()
        
        return total_delay
        pass

    def __init__(self, args):
        while True:
            print('Ping to: %s...' % (args.hostname))
            # Look up hostname, resolving it to an IP address
            ipAddress = socket.gethostbyname(args.hostname)

            delay = self.doOnePing(ipAddress, 10)
            delay = round(delay * 1000.0, 4)
        
            self.printOneResult(ipAddress, 50, delay, 150)
            time.sleep(1)


class Traceroute(NetworkApplication):
    MAX_JUMPS = 20

    def sendOnePing(self, icmpSocket, destinationAddress):
        dest = socket.gethostbyname(destinationAddress)

        checksum = 0

        header = struct.pack("bbHHh", 8, 0, checksum, 1, 1)
        checksum = NetworkApplication.checksum(self, header)
        header = struct.pack("bbHHh", 8, 0, checksum, 1, 1)

        icmpSocket.sendto(header, (destinationAddress, 0))

        time_sent = time.time()

        return time_sent

    def receiveOnePing(self, icmpSocket, timeLeft, time_sent, ttl):
        started_select = time.time()
        ready = select.select([icmpSocket], [], [], timeLeft)
        time_in_select = time.time() - started_select

        time_received = time.time()
        received_packet, addr = icmpSocket.recvfrom(1024)
        received_header = received_packet[20:28]
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh' , received_header)

        if type == 11:
            self.printOneResult(addr[0], 50, ((time_received - time_sent) * 1000), ttl)
        
        if type == 0:
            self.printOneResult(50, 50, ((time_received - time_sent) * 1000), ttl)
            print("Destination Reached")
        
        return time_received

    def doOneTraceRoute(self, destinationAddress, ttl, timeout, timeLeft):
        icmpSocket = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            socket.IPPROTO_ICMP
        )

        icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        icmpSocket.settimeout(timeout)

        time_sent = self.sendOnePing(icmpSocket, destinationAddress)
        self.receiveOnePing(icmpSocket, timeLeft, time_sent, ttl)

        icmpSocket.close()

    def fullTraceRoute(self, timeout):
        destinationAddress = socket.gethostbyname(args.hostname)
        timeLeft = timeout
        print('Traceroute to: %s...' % (args.hostname))

        for ttl in range(1, self.MAX_JUMPS):
            self.doOneTraceRoute(destinationAddress, ttl, timeout, timeLeft)
            time.sleep(1)

        return

    
    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        self.fullTraceRoute(timeout=15)





class WebServer(NetworkApplication):

    HOST = '127.0.0.1'  # localhost
    PORT = 4322        # Non-privileged port

    def handleRequest(self, tcpSocket, client_addr):
        # 1. Receive request message from the client on connection socket
        request = tcpSocket.recv(1024).decode('utf-8')
        string_list = request.split("/", 1)
        string_list2 = string_list[1].split(" ")
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        request_path = string_list2[0]
        print(string_list2[0])
        # 3. Read the corresponding file from disk
        try:
            file = open(request_path).read()
            header = 'HTTP/1.0 200 OK\n\n'
        except:
            file = "File not Found :("
            header = 'HTTP/1.0 404 Not Found\n\n'
        # 4. Store in temporary buffer
        # 5. Send the correct HTTP response error
        http_response = header + file
        # 6. Send the content of the file to the socket
        tcpSocket.sendall(http_response.encode())
        # 7. Close the connection socket
        tcpSocket.close()
        pass

    def __init__(self, args):
        # print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 2. Bind the server socket to server address and server port
        server_socket.bind((self.HOST , self.PORT))
        # 3. Continuously listen for connections to server socket
        server_socket.listen()
        connected_socket, client_addr = server_socket.accept()
        print('Connection from: ', client_addr)
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
        self.handleRequest(connected_socket, client_addr)
        # 5. Close server socket
        server_socket.close()


class Proxy(NetworkApplication):

    HOST = '127.0.0.1'
    PORT = 4321

    def handleRequest(self, tcpSocket, client_addr):
        # 1. Receive request message from client on connection socket
        request = tcpSocket.recv(1024).decode('utf-8')
        print(request)

        # 2. Split the message to extract the hostname of the request
        string_list = request.split('/' , 1)
        string_list2 = string_list[1].split('/' , 2)
        print(string_list2[1])

        # 3. Get the IP address of the request
        request_ip = socket.gethostbyname(string_list2[1])
        print(request_ip)
        request_port = 80

        header = 'HTTP/1.0 200 OK\n\n'

        http_request = request + header

        # 4. Connecting to the destination server 
        socket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket1.settimeout(1000)
        socket1.connect((request_ip , request_port))
        socket1.sendall(http_request.encode())

        # 5. Sending the server's response to the client socket.
        while 1:
            data = socket1.recv(1024)
            tcpSocket.send(data)



    def __init__(self, args):
        # print('Web Proxy starting on port: %i...' % (args.port))
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        server_socket.bind((self.HOST , self.PORT))

        server_socket.listen()

        connected_socket, client_addr = server_socket.accept()

        print('Connection from: ' , client_addr)

        self.handleRequest(connected_socket, client_addr)

        server_socket.close()



if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
