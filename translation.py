import argparse
import re

parser = argparse.ArgumentParser(description='Transform a match rule in a BPF program')
parser.add_argument('--filter', dest='filter', help='Filter using standard TCP dump syntax')
parser.add_argument('--openflow', dest='openflow', help='Filter using OpenFlow syntax')

args = parser.parse_args()


"""
   The format of the openflow rules, is each <field>=value(/mask)
   in_port
   eth_src
   eth_dst
   eth_type
   ip_proto
   ipv4_src
   ipv4_dst
   ipv6_src
   ipv6_dst
   tcp_src
   tcp_dst
   udp_src
   udp_dst
"""

IP_PROTO_TCP = 0x06
IP_PROTO_UDP = 0x11

if args.openflow:
    ofrule = args.openflow.split(' ')

    tcpdump_filter = {}
    for f in ofrule:
        key, val = f.split('=')

        if key == 'in_port':
            pass
        elif key == 'eth_src':
            tcpdump_filter['ether src'] = val
        elif key == 'eth_dst':
            tcpdump_filter['ether dst'] = val
        elif key == 'eth_type':
            tcpdump_filter['ether proto'] = val
        elif key == 'ip_proto':
            tcpdump_filter['ip proto'] = val
        elif key == 'ipv4_src':
            tcpdump_filter['ether proto'] = 'ipv4'
            tcpdump_filter['src host'] = val
        elif key == 'ipv4_dst':
            tcpdump_filter['ether proto'] = 'ipv4'
            tcpdump_filter['dst host'] = val
        elif key == 'ipv6_src':
            tcpdump_filter['ether proto'] = 'ipv6'
            tcpdump_filter['src host'] = val
        elif key == 'ipv6_dst':
            tcpdump_filter['ether proto'] = 'ipv6'
            tcpdump_filter['dst host'] = val
        elif key == 'tcp_src':
            tcpdump_filter['ip proto'] = IP_PROTO_TCP
            tcpdump_filter['tcp src port'] = val
        elif key == 'tcp_dst':
            tcpdump_filter['ip proto'] = IP_PROTO_TCP
            tcpdump_filter['tcp dst port'] = val
        elif key == 'udp_src':
            tcpdump_filter['ip proto'] = IP_PROTO_UDP
            tcpdump_filter['udp src port'] = val
        elif key == 'udp_dst':
            tcpdump_filter['ip proto'] = IP_PROTO_UDP
            tcpdump_filter['udp dst port'] = val


    print ' and '.join([ '{} {}'.format(k, v) for k, v in tcpdump_filter.items() ])

tcpdump_output = """{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 8, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 17, 0x00000011 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 14, 0, 0x00000016 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 12, 13, 0x00000016 },
{ 0x15, 0, 12, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 2, 0, 0x00000084 },
{ 0x15, 1, 0, 0x00000006 },
{ 0x15, 0, 8, 0x00000011 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00000016 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000016 },
{ 0x6, 0, 0, 0x00000000 },
{ 0x6, 0, 0, 0x0000ffff },"""

"""
    Want to add to the normal tcpdump syntax
    organisation id, protocol id, standard Id as well as the data
"""
if args.filter:
    l1_header_fields = { 'l1_length': 0, 'organisation_id': 1, 'protocol_id': 2, 'standard_id': 3 }
    operators = {
        '<' : '',
        '<=': '',
        '==': '',
        '>=': '',
        '>' : ''
    }

    tokens = args.filter.split(' ')

    l1_conditions = []

    for i, k in enumerate(tokens):
        if k in l1_header_fields.keys():
            # check if the next item is a number
            if tokens[i+1].isdigit():
                value = tokens[i+1]
            else:
                operator = tokens[i+1]
                if not (operator in operators.keys()):
                    print 'invalid operation'
                value = tokens[i+2]
                if not value.isdigit():
                    print 'expected a number got {}'.format(value)

            # print '{{ ldb, 0, 0, {} }}'.format(l1_header_fields[k])
            # print '{{ {}, 0, {}, 0x{:08x} }}'.format('jne', len(tcpdump_output.split('\n')), int(value))
            l1_conditions.append(())


        # elif k == 'in_port':


"""
    eBPF opcode encoding
  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)

Three LSB bits store instruction class which is one of:

  Classic BPF classes:    eBPF classes:

  BPF_LD    0x00          BPF_LD    0x00
  BPF_LDX   0x01          BPF_LDX   0x01
  BPF_ST    0x02          BPF_ST    0x02
  BPF_STX   0x03          BPF_STX   0x03
  BPF_ALU   0x04          BPF_ALU   0x04
  BPF_JMP   0x05          BPF_JMP   0x05
  BPF_RET   0x06          [ class 6 unused, for future if needed ]
  BPF_MISC  0x07          BPF_ALU64 0x07
"""

BPF_LD = 0x00
BPF_LDX = 0x01

"""
    Length, Organisation Id, Standard Id, Protocol Id (1 byte each)
    We assume for the time being that the frame is ethernet the only data is therefore port (32 bits)
    This gives a total header length of 8
"""

# Print the L1 filter
L1_HEADER_LENGTH = 8

# Print the L2+ filter
for opcode, jt, jf, k in re.findall('\{ (0x[0-9A-Fa-f]+), (\d+), (\d+), (0x[0-9A-Fa-f]+) \},\n', tcpdump_output):
    op = int(opcode, 16)

    # If it's a load operation we want to shift the memory to adjust for the L1 header
    if op & 0x7 in [BPF_LD, BPF_LDX]:
        k = '0x{:08x}'.format(int(k, 16) + L1_HEADER_LENGTH)

    print '{{ {}, {}, {}, {} }}'.format(opcode, jt, jf, k)
