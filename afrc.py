#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""afrc.py: Ejercicio de captura de paquetes de red."""
__author__ = ["Axel Eduardo Becerril Nájera", "Erick Carmona"]
__authors__ = ["Axel Eduardo Becerril Nájera", "Erick Carmona"]
__email__ = "axl@ciencias.unam.mx"
__version__ = "0.1"
__license__ = "BSD"
__status__ = "Development"

import argparse, pcapy, socket, sys, datetime
from struct import unpack
from sys import exit

def devs():
    """Muestra las interfaces de red disponibles."""

    try:
        print "Interfaces de red disponibles:"
        for d in pcapy.findalldevs():
            print "\t" + d
    except pcapy.PcapError:
        print "Error: No pudo accederse a los dispositivos. (¿Se cuenta con los privilegios necesarios?)"

def sniff(dev, snaplen=65536, promisc=True, timeout=0):
    # Abrir dispositivo para captura.
    cap = pcapy.open_live(dev, snaplen, promisc , timeout)

    # Iniciar la captura de paquetes
    print "Iniciando la captura de paquetes en " + dev + "."
    print "Presione ^C para detener."
    while True:
        try:
            (header, packet) = cap.next()
            parse(packet)
        except (KeyboardInterrupt, SystemExit):
            print "Terminando la captura de paquetes."
            exit()

def pretty_mac (addr) :
    pretty = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % tuple(map(ord, addr))
    return pretty

def parse(packet):
    eth_len=14
    eth_header = packet[:eth_len]
    eth = unpack('!6s6sH' , eth_header)

    print "◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦◦" # TODO: Un separador más majo.
    print "Direcciones MAC: " + pretty_mac(packet[0:6]) +  " → " + pretty_mac(packet[6:12])

    eth_protocol = socket.ntohs(eth[2])

    if eth_protocol == 8:   # IP Protocol 
        print "Protocolo: IP"
        ip_header = packet[eth_len:20+eth_len]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print "\tVersion: " + str(version)
        print "\tIP Header Length : " + str(ihl) 
        print "\tTTL : " + str(ttl) 
        print "\tProtocol : " + str(protocol) 
        print "\t" + str(s_addr) + " → " + str(d_addr)

        if protocol == 6 : #TCP protocol
            t = iph_length + eth_len
            tcp_header = packet[t:t+20]
 
            tcph = unpack('!HHLLBBHHH' , tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
             
            print "\tSource Port: " + str(source_port) 
            print "\tDest Port: " + str(dest_port) 
            print "\tSequence Number: " + str(sequence) 
            print "\tAcknowledgement: " + str(acknowledgement) 
            print "\tTCP header length: " + str(tcph_length)
             
            h_size = eth_len + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            print "\tData : " + data
 
        elif protocol == 1 :    # ICMP
            u = iph_length + eth_len
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print "\tType: " + str(icmp_type) 
            print "\tCode: " + str(code) 
            print "\tChecksum: " + str(checksum)
             
            h_size = eth_len + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            print "\tData: " + data
 
        elif protocol == 17 :   # UDP
            u = iph_length + eth_len
            udph_length = 8
            udp_header = packet[u:u+8]
 
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print "\tSource Port: " + str(source_port) 
            print "\tDest Port: " + str(dest_port) 
            print "\tLength: " + str(length) 
            print "\tChecksum: " + str(checksum)
             
            h_size = eth_len + iph_length + udph_length
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            print "\tData: " + data
 
        else :  # TODO
            print "Protocolo no identificado."

def main():
    parser = argparse.ArgumentParser(description='Ejercicio de captura de paquetes de red')
    # Opción para hacer el listado de dispositivos de red
    parser.add_argument('-ls', '--list-devices', dest='devices', action='store_const', const=devs,
            required=False, help=devs.__doc__)
    # Opción para iniciar la captura de paquetes
    parser.add_argument('--sniff', nargs=1, metavar='dispositivo', help="Inicia la captura de paquetes en el dispositivo indicado.")

    args = parser.parse_args()

    if args.devices:
        args.devices()
    elif args.sniff:
        sniff(dev=args.sniff[0])

if __name__ == "__main__":
    main()
