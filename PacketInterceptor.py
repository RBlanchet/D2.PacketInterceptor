from struct import pack
from scapy.all import sniff, Raw, IP, ICMP
from CustomDataWrapper import Buffer
import socketio

class PacketInterceptor:
    def __init__(self):
        self.sio = socketio.Client()
        self.sio.connect('http://localhost:3000')
        self.lastPacket = None
        self.buffer = Buffer()
        sniff(
            filter='tcp src port 5555',
            lfilter = lambda packet: packet.haslayer(Raw),
            prn = lambda packet: self.receive(packet)
        )
    
    def receive(self, packet):
        if self.lastPacket and packet.getlayer(IP).src != self.lastPacket.getlayer(IP).src:
            self.lastPacket = None
        if self.lastPacket and packet.getlayer(IP).id < self.lastPacket.getlayer(IP).id:
            self.buffer.reorder(bytes(packet.getlayer(Raw)), len(self.lastPacket.getlayer(Raw)))
        else:
            self.buffer = Buffer()
            self.buffer += bytes(packet.getlayer(Raw))
        self.lastPacket = packet
        self.sio.emit('data', {
            'data': self.buffer.data.hex()
        })
        print(self.buffer.data.hex())