from CSVPacket import Packet, CSVPackets
import sys
from collections import defaultdict, Counter


def print_packet_summary(num_packets, num_bytes, ip_protocols):
    print(f"Packet: {num_packets} Bytes: {num_bytes}")
    for i, count in enumerate(ip_protocols):
        if count > 0:
            print(f"{i:3d}: {count:9d}")


def read_csv_packets(csvfile):
    return list(CSVPackets(csvfile))


def stats():
    print("\n\nSTATS\n")
    csv_filename = sys.argv[1]
    print(f"{csv_filename}\n\n")

    ip_protocols = [0] * 256
    tcp_ports = [0] * 1025
    udp_ports = [0] * 1025
    num_bytes = num_packets = 0

    with open(csv_filename, 'r') as csvfile:
        packets = read_csv_packets(csvfile)
        for pkt in packets:
            num_bytes += pkt.length
            num_packets += 1
            ip_protocols[pkt.proto & 0xff] += 1

            if pkt.proto == 6 and pkt.tcpdport <= 1024:
                tcp_ports[pkt.tcpdport] += 1
            elif pkt.proto == 17 and pkt.udpdport <= 1024:
                udp_ports[pkt.udpdport] += 1

    print_packet_summary(num_packets, num_bytes, ip_protocols)
    for port, count in enumerate(tcp_ports):
        if count > 0:
            print(f"TCP Packets going to port {port}: {count}")
    for port, count in enumerate(udp_ports):
        if count > 0:
            print(f"UDP Packets going to port {port}: {count}")


def countip():
    print("\n\nCOUNTIP\n")
    csv_filename = sys.argv[1]
    print(f"{csv_filename}\n\n")

    ip_protocols = [0] * 256
    num_bytes = num_packets = 0
    ip_addresses = []

    with open(csv_filename, 'r') as csvfile:
        packets = read_csv_packets(csvfile)
        for pkt in packets:
            num_bytes += pkt.length
            num_packets += 1
            ip_protocols[pkt.proto & 0xff] += 1
            if len(sys.argv) < 4 or (
                sys.argv[3] == "-GRE" and pkt.proto == 47
                or sys.argv[3] == "-IPSEC" and pkt.proto in {50, 51}
                or sys.argv[3] == "-OSPF" and pkt.proto == 89
            ):
                ip_addresses.extend([pkt.ipsrc, pkt.ipdst])

    print_packet_summary(num_packets, num_bytes, ip_protocols)
    unique_ips = Counter(ip_addresses)
    for ip, count in unique_ips.most_common():
        print(f"({ip}, {count})")


def connto():
    """Analyze connections to destination IPs."""
    print("\n\nCONNTO\n")
    csv_filename = sys.argv[1]
    print(f"{csv_filename}\n\n")

    ip_protocols = [0] * 256
    num_bytes = num_packets = 0
    dest_ips = defaultdict(lambda: [set(), set()])

    with open(csv_filename, 'r') as csvfile:
        packets = read_csv_packets(csvfile)
        for pkt in packets:
            num_bytes += pkt.length
            num_packets += 1
            ip_protocols[pkt.proto & 0xff] += 1

            if pkt.proto == 6 and pkt.tcpdport <= 1024:
                dest_ips[pkt.ipdst][0].add(pkt.ipsrc)
                dest_ips[pkt.ipdst][1].add(f"tcp/{pkt.tcpdport}")
            elif pkt.proto == 17 and pkt.udpdport <= 1024:
                dest_ips[pkt.ipdst][0].add(pkt.ipsrc)
                dest_ips[pkt.ipdst][1].add(f"udp/{pkt.udpdport}")

    print_packet_summary(num_packets, num_bytes, ip_protocols)
    sorted_dest_ips = sorted(
        dest_ips.items(), key=lambda item: (len(item[1][0]), item[0]), reverse=True
    )
    for i, (ip_dst, (src_ips, ports)) in enumerate(sorted_dest_ips[:20], start=1):
        print(f"ipdst {ip_dst} has {len(src_ips)} distinct ipsrc on ports: {', '.join(ports)}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <file.csv> <-stats|-countip|-connto>")
    elif sys.argv[2] == "-stats":
        stats()
    elif sys.argv[2] == "-countip":
        countip()
    elif sys.argv[2] == "-connto":
        connto()
