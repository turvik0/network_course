import socket
import heapq
import logging
import uuid

MAX_PACKET_SIZE = 1514
MAX_HEADER_SIZE = 8
MAX_DATA_SIZE = MAX_PACKET_SIZE - MAX_HEADER_SIZE
MAX_CONFIRMATION_RETRIES = 32

LOGGER = logging.getLogger(__name__)

class Header:
    def __init__(self, seq_num, ack_num):
        self.seq_num = seq_num
        self.ack_num = ack_num

    def __bytes__(self):
        return self.seq_num.to_bytes(4, 'big') + self.ack_num.to_bytes(4, 'big')

    @classmethod
    def from_bytes(cls, data_bytes):
        seq_num = int.from_bytes(data_bytes[:4], 'big')
        ack_num = int.from_bytes(data_bytes[4:], 'big')
        return cls(seq_num, ack_num)

class TCPPacket:
    def __init__(self, data, seq_num=None, ack_num=None, header=None):
        if header:
            self.header = header
        else:
            self.header = Header(seq_num, ack_num)
        self.data = data

    def __bytes__(self):
        return bytes(self.header) + self.data

    @classmethod
    def from_bytes(cls, data_bytes):
        header = Header.from_bytes(data_bytes[:MAX_HEADER_SIZE])
        data = data_bytes[MAX_HEADER_SIZE:]
        return cls(data, header=header)

    def __lt__(self, other):
        return self.header.seq_num < other.header.seq_num

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, buffer_size):
        msg, _ = self.udp_socket.recvfrom(buffer_size)
        return msg

    def close(self):
        self.udp_socket.close()

class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_socket.settimeout(0.001)
        self.sent_data_len = 1
        self.recv_data_len = 1
        self.uuid = uuid.uuid4()
        self.buffer = []
        self.buffered_data = b''

    def send(self, data: bytes):
        initial_sent_len = self.sent_data_len
        total_data_len = len(data)
        confirmation_retries = 0

        data_offset = self.sent_data_len - initial_sent_len
        num_packets = (total_data_len + MAX_DATA_SIZE - 1) // MAX_DATA_SIZE

        for i in range(num_packets):
            packet_data = data[data_offset + i * MAX_DATA_SIZE: data_offset + (i + 1) * MAX_DATA_SIZE]
            packet = TCPPacket(
                packet_data,
                seq_num=self.sent_data_len + i * MAX_DATA_SIZE,
                ack_num=self.recv_data_len
            )
            self.sendto(bytes(packet))

        while self.sent_data_len < initial_sent_len + total_data_len:
            try:
                recvd_bytes = self.recvfrom(MAX_PACKET_SIZE)
                recvd_packet = TCPPacket.from_bytes(recvd_bytes)
                recvd_header = recvd_packet.header
                confirmation_retries = 0

                if recvd_header.seq_num > 0:
                    if recvd_header.seq_num == self.recv_data_len:
                        self.buffered_data += recvd_packet.data
                        self.recv_data_len += len(recvd_packet.data)
                        self.buffered_data += self._process_buffer()
                    else:
                        heapq.heappush(self.buffer, recvd_packet)
                    self._send_ack()
                    continue

                if recvd_header.ack_num <= self.sent_data_len:
                    continue

                self.sent_data_len = recvd_header.ack_num
            except Exception:
                confirmation_retries += 1
                if confirmation_retries > MAX_CONFIRMATION_RETRIES:
                    break

            if self.sent_data_len < initial_sent_len + total_data_len:
                offset = self.sent_data_len - initial_sent_len
                packet_data = data[offset: offset + MAX_DATA_SIZE]
                packet = TCPPacket(
                    packet_data,
                    seq_num=self.sent_data_len,
                    ack_num=self.recv_data_len
                )
                self.sendto(bytes(packet))

        self.sent_data_len = initial_sent_len + total_data_len
        return total_data_len

    def _process_buffer(self):
        final_data = b''
        while self.buffer and self.buffer[0].header.seq_num <= self.recv_data_len:
            packet = heapq.heappop(self.buffer)
            if packet.header.seq_num < self.recv_data_len:
                continue
            final_data += packet.data
            self.recv_data_len += len(packet.data)
        return final_data

    def _send_ack(self):
        ack_packet = Header(seq_num=0, ack_num=self.recv_data_len)
        self.sendto(bytes(ack_packet))

    def recv(self, n: int):
        initial_recv_size = self.recv_data_len
        final_data = self.buffered_data[:n]
        self.buffered_data = self.buffered_data[n:]
        n -= len(final_data)

        while self.recv_data_len < initial_recv_size + n:
            try:
                final_data += self._process_buffer()
                recvd_bytes = self.recvfrom(MAX_PACKET_SIZE)
                recvd_packet = TCPPacket.from_bytes(recvd_bytes)

                if recvd_packet.header.seq_num < self.recv_data_len:
                    continue

                if recvd_packet.header.seq_num == self.recv_data_len:
                    final_data += recvd_packet.data
                    self.recv_data_len += len(recvd_packet.data)
                    final_data += self._process_buffer()
                else:
                    heapq.heappush(self.buffer, recvd_packet)
            except Exception:
                self._send_ack()

        self._send_ack()
        return final_data

    def close(self):
        super().close()
