import struct
from socket import IPPROTO_UDP, inet_aton, inet_ntoa

BYTES_PER_WORD = 4
L3_PSEUDO_HEADER_STRUCT = "!LLBBH"


class InvalidHWAddr(Exception):
    """
    An error to throw when an invalid mac address is passed to a function
    """
    pass


def swap_endianess_16(a):
    """
    Swap the endianness of a 16 bit number
    :param a: number to swap
    :return: the number with the endianness swapped
    """
    return struct.unpack("<H", struct.pack(">H", a))[0]


def carry_around_add(a, b):
    """
    Function to add two 16 bit numbers and carry around the sum's remainder
    :param a: first integer to add
    :param b: second integer to add
    :return: the wrapped around addition of a and b
    """
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(msg):
    """
    Calculate the 16 bit ones-compliment checksum on the passed bytes
    :param msg: the bytes to calculate the checksum on
    :return: the checksum as a 16 bit number
    """
    s = 0
    # add padding
    if len(msg) % 2 == 1:
        msg += b'\x00'
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s = carry_around_add(s, w)
    csum = ~s & 0xffff
    # the entire calculation was done in big endian, but we want it in little for our computer
    return swap_endianess_16(csum)


def generate_pseudo_header(src_ip, dst_ip, l3_proto, l3_tot_len):
    return struct.pack(
        L3_PSEUDO_HEADER_STRUCT,
        struct.unpack("!L", src_ip)[0],
        struct.unpack("!L", dst_ip)[0],
        0,
        l3_proto,
        l3_tot_len
    )


class BaseProtocol:
    @staticmethod
    def parse_raw_header(raw_header_bytes):
        raise NotImplementedError

    def get_raw_header(self):
        raise NotImplementedError

    @property
    def length(self):
        raise NotImplementedError


class EtherHeader(BaseProtocol):
    """
    Class for parsing and creating raw ethernet headers
    """
    TOTAL_HEADER_LEN = 14
    MAC_ADDR_LEN = 6

    @staticmethod
    def get_mac_bytes_from_str(str_addr, divider=':'):
        """
        Get a bytes object (length of 6) of the passed canonical string mac address
        :param str_addr: the address as a string
        :param divider: the divider between each octet of the address in the string (ie, aa:aa:aa:aa:aa:aa is ':')
        :return: a bytes object representing the address
        """
        bytes_as_str = str_addr.split(divider)
        if len(bytes_as_str) != EtherHeader.MAC_ADDR_LEN:
            raise InvalidHWAddr('{} is not a valid mac address with divider {}'.format(str_addr, divider))
        return bytes.fromhex(" ".join(bytes_as_str))

    @staticmethod
    def get_str_from_mac_bytes(raw_bytes, divider=':'):
        """
        Get a string representing a raw mac address
        :param raw_bytes: the raw bytes of the mac address
        :param divider: the divider between each octet of the string address
        :return: a string representing the address
        """
        return divider.join(hex(byte)[2:].zfill(2) for byte in raw_bytes)

    @staticmethod
    def parse_raw_header(raw_header_bytes):
        """
        Parse the passed bytes into an EtherHeader object
        :param raw_header_bytes: the raw bytes to parse
        :return: an EtherHeader object and the number of bytes parsed
        """
        raw_header_bytes = raw_header_bytes[:EtherHeader.TOTAL_HEADER_LEN]
        dst_addr = raw_header_bytes[: EtherHeader.MAC_ADDR_LEN]
        src_addr = raw_header_bytes[EtherHeader.MAC_ADDR_LEN: EtherHeader.MAC_ADDR_LEN * 2]
        l3_proto = raw_header_bytes[EtherHeader.MAC_ADDR_LEN * 2: EtherHeader.MAC_ADDR_LEN * 2 + 2]
        return EtherHeader(src_addr, dst_addr, l3_proto), EtherHeader.TOTAL_HEADER_LEN

    def __init__(self, src_addr, dst_addr, l3_proto):
        # user can pass addresses as canonical strings or bytes object
        if isinstance(src_addr, str):
            self.src_addr = type(self).get_mac_bytes_from_str(src_addr)
        else:
            self.src_addr = src_addr
        if isinstance(dst_addr, str):
            self.dst_addr = type(self).get_mac_bytes_from_str(dst_addr)
        else:
            self.dst_addr = dst_addr

        if isinstance(l3_proto, int):
            #  unsigned short in network byte order
            self.l3_proto = struct.pack('!H', l3_proto)
        else:
            self.l3_proto = l3_proto

    @property
    def dst_addr_str(self):
        return type(self).get_str_from_mac_bytes(self.dst_addr)

    @property
    def src_addr_str(self):
        return type(self).get_str_from_mac_bytes(self.src_addr)

    def length(self):
        return type(self).TOTAL_HEADER_LEN

    def get_raw_header(self):
        """
        Get the raw bytes of the header
        :return: bytes object
        """
        return self.dst_addr + self.src_addr + self.l3_proto


class IpHeader(BaseProtocol):
    """
    Class for parsing and creating raw IP headers
    """
    DEFAULT_IHL = 5
    DEFAULT_HEADER_SIZE = DEFAULT_IHL * BYTES_PER_WORD
    IPV4 = 4
    DEFAULT_TTL = 255
    NO_FLAGS = 0
    NO_FRAG_OFFSET = 0
    RAW_HEADER_STRUCT = '!BBHHHBBHII'
    RAW_HEADER_FIELDS = ['version_ihl', 'tos', 'total_len', 'id', 'frag_offset', 'ttl', 'proto', 'checksum', 'src_ip',
                         'dst_ip']

    @staticmethod
    def _get_version_ihl_from_byte(version_ihl_byte):
        """
        parse the byte representing the version and ihl into the upper and lower halves
        :param version_ihl_byte: the version_ihl byte to parse
        :return: the version and ihl as a tuple
        """
        version = (version_ihl_byte & 0xf0) >> 4
        ihl = (version_ihl_byte & 0xf)
        return version, ihl

    @staticmethod
    def parse_raw_header(raw_header_bytes):
        """
        Parse te raw bytes of an ip header to an IpHeader object
        :param raw_header_bytes: raw bytes of the header
        :return: IP header object + number of bytes parsed
        """
        raw_header_bytes = raw_header_bytes[:IpHeader.DEFAULT_HEADER_SIZE]
        parsed_fields = struct.unpack(IpHeader.RAW_HEADER_STRUCT, raw_header_bytes)
        version_ihl, tos, total_len, id, frag_offset, ttl, proto, checksum, src_ip, dst_ip = parsed_fields
        version, ihl = IpHeader._get_version_ihl_from_byte(version_ihl)
        ip_header = IpHeader(src_ip, dst_ip)
        ip_header.version = version
        ip_header.ihl = ihl
        ip_header.tos = tos
        ip_header.tot_len = total_len
        ip_header.id = id
        ip_header.frag_off = frag_offset
        ip_header.ttl = ttl
        ip_header.proto = proto
        ip_header.check = checksum

        return ip_header, ip_header.DEFAULT_HEADER_SIZE

    def __init__(self, src_ip, dst_ip, l4_proto=IPPROTO_UDP, id=0):
        self.ihl = type(self).DEFAULT_IHL
        self.version = type(self).IPV4
        self.tos = type(self).NO_FLAGS
        self.tot_len = None
        self.id = id
        self.frag_off = type(self).NO_FRAG_OFFSET
        self.ttl = type(self).DEFAULT_TTL
        self.proto = l4_proto
        self.check = None
        if isinstance(src_ip, str):
            self.src_ip = inet_aton(src_ip)
        elif isinstance(src_ip, int):
            self.src_ip = struct.pack("!L", src_ip)
        else:
            self.src_ip = src_ip
        if isinstance(src_ip, str):
            self.dst_ip = inet_aton(dst_ip)
        elif isinstance(src_ip, int):
            self.dst_ip = struct.pack("!L", dst_ip)
        else:
            self.dst_ip = dst_ip

    def _get_version_ihl_byte(self):
        """
        Calculate the byte value of the version/ihl byte based on this object's version and ihl value
        :return:
        """
        return ((self.version & 0xf) << 4) | (self.ihl & 0xf)

    def fill_payload_dependent_fields(self, payload):
        """
        Calculate and fill out the fields that are dependent on the l4 payload
        :param payload: the l4 payload
        :return: None
        """
        self.check = 0
        self.tot_len = self.ihl * BYTES_PER_WORD + len(payload)
        self.check = checksum(self.get_raw_header())

    @property
    def src_ip_str(self):
        return inet_ntoa(self.src_ip)

    @property
    def dst_ip_str(self):
        return inet_ntoa(self.dst_ip)

    def get_raw_header(self):
        raw_ip_header = struct.pack(
            type(self).RAW_HEADER_STRUCT,
            self._get_version_ihl_byte(),
            self.tos,
            self.tot_len,
            self.id,
            self.frag_off,
            self.ttl,
            self.proto,
            self.check,
            struct.unpack("!L", self.src_ip)[0],
            struct.unpack("!L", self.dst_ip)[0]
        )
        return raw_ip_header

    def length(self):
        return struct.calcsize(type(self).RAW_HEADER_STRUCT)

    def __str__(self):
        return 'IP From: {} To: {}'.format(
            self.src_ip_str,
            self.dst_ip_str
        )


class UdpHeader(BaseProtocol):
    RAW_HEADER_STRUCT = "!HHHH"
    UDP_HEADER_SIZE = 8

    @staticmethod
    def parse_raw_header(raw_header_bytes):
        raw_header_bytes = raw_header_bytes[:UdpHeader.UDP_HEADER_SIZE]
        src_port, dst_port, udp_len, checksum = struct.unpack(UdpHeader.RAW_HEADER_STRUCT, raw_header_bytes)
        return UdpHeader(src_port, dst_port, udp_len, checksum), UdpHeader.UDP_HEADER_SIZE

    def __init__(self, src_port, dst_port, udp_len, checksum):
        self.src_port = src_port
        self.dst_port = dst_port
        self.udp_len = udp_len
        self.checksum = checksum
        self.pseudo_header = b''

    def fill_payload_dependent_fields(self, payload):
        self.udp_len = type(self).UDP_HEADER_SIZE + len(payload)
        self.checksum = 0
        self.checksum = checksum(self.pseudo_header + self.get_raw_header() + payload)

    def get_raw_header(self):
        return struct.pack(
            type(self).RAW_HEADER_STRUCT,
            self.src_port,
            self.dst_port,
            self.udp_len,
            self.checksum
        )

    def length(self):
        return struct.calcsize(type(self).RAW_HEADER_STRUCT)


class TcpHeader(BaseProtocol):
    RAW_HEADER_STRUCT = "!HHLLHHHH"
    DEFAULT_TCP_HEADER_SIZE = 20

    @staticmethod
    def parse_raw_header(raw_header_bytes):
        raw_header_bytes = raw_header_bytes[:TcpHeader.DEFAULT_TCP_HEADER_SIZE]
        unpacked_values = struct.unpack(TcpHeader.RAW_HEADER_STRUCT, raw_header_bytes)
        src_port, dst_port, seq_num, ack_num, offset_and_flags, window_size, checksum, urgent_ptr = unpacked_values
        tcp_header = TcpHeader(src_port, dst_port, seq_num, ack_num, offset_and_flags, window_size, checksum,
                               urgent_ptr)
        return tcp_header, TcpHeader.DEFAULT_TCP_HEADER_SIZE

    def __init__(self, src_port, dst_port, seq_num, ack_num, offset_and_flags, window_size, checksum, urgent_ptr):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.offset_and_flags = offset_and_flags
        self.window_size = window_size
        self.checksum = checksum
        self.urgent_ptr = urgent_ptr

        self.pseudo_header = b''

    def fill_payload_dependent_fields(self, payload):
        self.checksum = 0
        self.checksum = checksum(self.pseudo_header + self.get_raw_header() + payload)

    def get_raw_header(self):
        return struct.pack(
            type(self).RAW_HEADER_STRUCT,
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            self.offset_and_flags,
            self.window_size,
            self.checksum,
            self.urgent_ptr,
        )

    def length(self):
        return struct.calcsize(type(self).RAW_HEADER_STRUCT)


class UnknownProtocol(BaseProtocol):
    """
    Represents a header we can't identify
    Just has the unidentified raw bytes in a single field
    """

    @staticmethod
    def parse_raw_header(raw_header_bytes):
        return UnknownProtocol(raw_header_bytes), len(raw_header_bytes)

    def __init__(self, raw_bytes):
        self.raw_bytes = raw_bytes

    def get_raw_header(self):
        return self.raw_bytes

    def length(self):
        return len(self.raw_bytes)
