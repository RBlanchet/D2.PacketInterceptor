from struct import pack
from scapy.all import AsyncSniffer, sniff, Raw, IP, ICMP
from CustomDataWrapper import Buffer
import sys

class PacketInterceptor:
    def __init__(self):
        self.lastPacket = None
        self.buffer = Buffer()
        self.sniffer = sniff(
            filter="tcp src port 5555",
            lfilter = lambda packet: packet.haslayer(Raw),
            prn = lambda packet: self.receive(packet)
        )
    
    def run(self):
        self.sniffer.start()

    def stop(self):
        self.sniffer.stop()

    def receive(self, packet):
        if self.lastPacket and packet.getlayer(IP).src != self.lastPacket.getlayer(IP).src:
            self.lastPacket = None
        if self.lastPacket and packet.getlayer(IP).id < self.lastPacket.getlayer(IP).id:
            self.buffer.reorder(bytes(packet.getlayer(Raw)), len(self.lastPacket.getlayer(Raw)))
        else:
            self.buffer = Buffer()
            self.buffer += bytes(packet.getlayer(Raw))
        self.lastPacket = packet
        print(self.buffer.data.hex())
        sys.stdout.flush()
