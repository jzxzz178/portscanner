import argparse
import re
import socket
from queue import Queue, Empty
from threading import Thread
from datetime import datetime
import signal
from time import time

import scapy
from scapy.data import TCP_SERVICES
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.sendrecv import sr1, sr
from scapy.volatile import RandShort

TCP_REVERSE = dict((k, TCP_SERVICES[k]) for k in TCP_SERVICES.keys())


class Portscan:
    def __init__(self):
        args = self.parse_arguments()
        self.dest_ip = args.dest_ip
        self.ports = args.ports
        if args.timeout:
            self.timeout = args.timeout
        else:
            self.timeout = 2
        self.treads_count = args.treads_count
        self.p_proto_show = args.guess
        self.verbose = args.verbose

    def parse_arguments(self):
        parser = argparse.ArgumentParser(description="portscanner")
        parser.add_argument("-t", "--timeout", help="Specify timeout", type=int, required=False, default=2)
        parser.add_argument("-j", "--num-threads", dest="treads_count", type=int,
                            help="Specify tread count", required=False, default=4)
        parser.add_argument("-g", "--guess", action='store_true')
        parser.add_argument("-v", "--verbose", action='store_true')
        parser.add_argument("dest_ip", type=str, help="Destanation ip")
        parser.add_argument("ports", type=str, nargs="+", help="Protocol(TCP/UDP)/port(s)")
        args = parser.parse_args()
        return args

    def run(self):
        queue = Queue()
        for item in self.ports:
            proto, ports = item.split("/")[0], item.split("/")[1]
            for port in ports.split(","):
                if proto.upper() == "UDP":
                    if "-" in port:
                        for p in range(int(port.split("-")[0]), int(port.split("-")[1]) + 1):
                            queue.put(self.udp_scan(self.dest_ip, p, self.timeout))
                    else:
                        queue.put(self.udp_scan(self.dest_ip, port, self.timeout))
                elif proto.upper() == "TCP":
                    if "-" in port:
                        for p in range(int(port.split("-")[0]), int(port.split("-")[1]) + 1):
                            queue.put(self.tcp_scan(self.dest_ip, p, self.timeout))
                    else:
                        queue.put(self.tcp_scan(self.dest_ip, port, self.timeout))
            consumers = []
            for t in range(self.treads_count):
                consumer_thread = Thread(
                    target=self.consumer,
                    args=(queue,),
                    daemon=True
                )
                consumers.append(consumer_thread)
                consumer_thread.start()
            queue.join()

    def consumer(self, queue: Queue):
        while True:
            try:
                item = queue.get()
                queue.task_done()
            except Empty:
                continue

    def udp_scan(self, target, port, timeout):
        # print("udp scan on %s with ports %s" % (target, ports))
        port = int(port)
        start_time = time()
        pkt = sr1(IP(dst=target) / UDP(dport=port), timeout=timeout, verbose=0)
        spent_time = round((time() - start_time) * 1000)
        counter = 0
        start_time = time()
        while not pkt and counter < 10:
            pkt = sr1(IP(dst=target) / UDP(dport=port), timeout=timeout / 10, verbose=0)
            counter += 1

        spent_time = round((time() - start_time) * 1000)
        app_protocol = '-'
        if TCP_REVERSE.__contains__(port):
            app_protocol = TCP_REVERSE[port]

        if pkt is None:
            self.print_ports(port, 'UDP', str(spent_time), app_protocol)
        else:
            if pkt.haslayer(ICMP):
                self.print_ports(port, "Closed")
            if pkt.haslayer(UDP):
                self.print_ports(port, 'UDP', str(spent_time), app_protocol)

            # else:
            #     self.print_ports(port, "Unknown")
            #     print(pkt.summary())

    def tcp_scan(self, target, port, timeout):
        sport = RandShort()
        start_time = time()
        port = int(port)
        package = sr1(IP(dst=target) / TCP(sport=sport, dport=int(port), flags="S"), timeout=timeout, verbose=0)
        # print(*package)
        # print(*unans)
        spend_time = round((time() - start_time) * 1000)
        p_proto = self.get_app_protocol(package)
        # print(f'{p_proto}, {socket.getservbyname(str(port))}')
        if package is not None:
            summary = package.summary()
            if package.haslayer(TCP):
                if package[TCP].flags == 20:
                    pass
                elif package[TCP].flags == 18:
                    self.print_ports(port, "TCP", str(spend_time), p_proto)
                else:
                    self.print_ports(port, "TCP", str(spend_time), p_proto, "TCP packet resp / filtered")
            elif package.haslayer(ICMP):
                self.print_ports(port, "TCP", str(spend_time), p_proto, "ICMP resp / filtered")
            else:
                self.print_ports(port, "TCP", str(spend_time), msg="Unknown resp")
                print(package.summary())

    def print_ports(self, port, proto, spent_time=None, app_protocol="-", msg=''):
        print(f'{proto.upper()} {port}', end=' ')
        if spent_time:
            print(f'{spent_time}, ms', end=' ')
        print(app_protocol)
        # print(f"Protocol: {proto}, port: {port}", end=" ")
        # print(f", Application layer protocol: {app_protocol}", end=" ")
        # print(f", Spend time: {spent_time} ms", end=" ")
        # if msg:
        #     print(f"msg = {msg}", end=" ")
        # print("")

    def get_app_protocol(self, packet: scapy.layers.inet.IP):
        try:
            # pattern = r':\w+\s'
            pattern = r':(\w+) >'
            summary = packet.summary()
            # print(summary)
            # return summary
            p_proto = re.search(pattern, summary)[0]
            return p_proto[1:-1]
        except Exception:
            return None


if __name__ == '__main__':
    p = Portscan()
    p.run()
