from socket import *
from ctypes import create_string_buffer, addressof
from struct import pack

L3_PROTO_IP = 0x0800
MAX_BUF_SIZE = 212992
SO_ATTACH_FILTER = 26

RAW_TCPDUMP_FILTER = """{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 3, 0x00000800 },
{ 0x20, 0, 0, 0x0000001a },
{ 0x15, 0, 1, 0xc0a8017f },
{ 0x6, 0, 0, 0xffffffff },
{ 0x6, 0, 0, 0x00000000 },
"""

def pack_bpf_code_line(opcode, jt, jf, k):
    return pack('HBBI', opcode, jt, jf, k)

def get_filter_from_tcpdump_str(tcpdump_dd_str):
    macroString = '( ' + tcpdump_dd_str.replace(
        '\n', '').replace('{', '[').replace('}', ']') + ')'
    code_list = eval(macroString)

    bpf_buffer = b''
    for code_line in code_list:
        print(code_line)
        bpf_buffer += pack_bpf_code_line(*code_line)
    #print(bpf_buffer)
    b = create_string_buffer(bpf_buffer)
    for byte in b:
        print(byte)
    mem_addr_of_filters = addressof(b)
    print(len(code_list), hex(mem_addr_of_filters))
    fprog = pack('<HQ', len(code_list), mem_addr_of_filters)
    print(fprog)
    return fprog

def create_raw_ip_socket(interface):
    #fprog = get_filter_from_tcpdump_str(RAW_TCPDUMP_FILTER)

    raw_sock = socket(AF_PACKET, SOCK_RAW, L3_PROTO_IP)

    raw_sock.setsockopt(SOL_SOCKET, SO_RCVBUF, MAX_BUF_SIZE)
    #raw_sock.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, fprog)

    raw_sock.bind((interface, L3_PROTO_IP))

    return raw_sock


