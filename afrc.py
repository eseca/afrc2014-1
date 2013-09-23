#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""afrc.py: Ejercicio de captura de paquetes de red."""
__author__ = ["Axel Eduardo Becerril Nájera", "Erick Carmona Jiménez"]
__authors__ = ["Axel Eduardo Becerril Nájera", "Erick Carmona Jiménez"]
__email__ = "axl@ciencias.unam.mx"
__version__ = "0.1"
__license__ = "BSD"
__status__ = "Development"

import argparse, pcapy, socket, sys, datetime, struct
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

def sniff(dev, snaplen=65536, promisc=True, timeout=0, dump=None):
    """Inicia la captura de paquetes en el dispositivo indicado."""

    # Abrir dispositivo para captura.
    cap = pcapy.open_live(dev, snaplen, promisc , timeout)

    # Abrir dumpfile
    if dump is not None:
        d = cap.dump_open(dump)
    else:
        d = None

    # Iniciar la captura de paquetes
    print "Iniciando la captura de paquetes en " + dev + "."
    print "Presione ^C para detener."
    while True:
        try:
            (header, packet) = cap.next()
            parse(packet)
            if d is not None:
                d.dump(header, packet)

        except (KeyboardInterrupt, SystemExit):
            print "Terminando la captura de paquetes."
            exit()

def offline(filename):
    """Anaiza un archivo pcap."""
    print "Abriendo archivo «" + filename + "»..."
    cap = pcapy.open_offline(filename)
    while True:
        (header, packet) = cap.next()
        if header != None:
            parse(packet)
        else:
            break

def pretty_mac (addr) :
    """Formatea una dirección MAC."""
    pretty = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % tuple(map(ord, addr))
    return pretty

def parse(packet):
    """Interpreta los paquetes"""
    # TODO: Limpiar esta función abstrayendo a clases los paquetes.

    # 0123456789012345678901234567890123456789012345678901234567890123
    # Ethernet Version 2
    # PPPPPPPPDDDDDDSSSSSSTTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxFFFF
    # IEEE 802.3 
    # PRRRRRRRDDDDDDSSSSSSLLdsccxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxFFFF
    # IEEE 802.3 SNAP header
    # PRRRRRRRDDDDDDSSSSSSLLdscOOOTTxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxFFFF

    eth_len=14
    eth_header = packet[:eth_len]
    #try:
    eth = unpack('!6s6sH' , eth_header)
    #except struct.error:
    #    print "! No se pudo leer la cabecera ethernet"
    #    return 1

    if eth[2] <= 0x05DC:
        dsc = unpack('!3B', packet[eth_len:eth_len+3])
        if dsc == (0xAA, 0xAA, 0x03):
            print "IEEE 802.3 Ethernet SNAP"
            snap = unpack('!3sH', packet[eth_len+3:eth_len+8])
            eth_protocol = snap[1]
            eth_len=22  # Ajustar cabecera eth
        else:
            print "IEEE 802.3 Ethernet"
            print "DSAP:%.2x SSAP:%.2x" % tuple(dsc[:2],)
            # TODO Basado señales. Abstraer protocolos en clases:
            eth_protocol = 0x0800 if dsc[0] == 0x06 else None
            eth_len=18  # Ajustar cabecera eth
    else:
        print "Ethernet Version 2"
        eth_protocol = eth[2]

    print pretty_mac(eth[0]) +  " → " + pretty_mac(eth[1])

    if eth_protocol == 0x0800:     # IP Protocol 
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

        print "|\tVersion: " + str(version)
        print "|\tIP Header Length : " + str(ihl) 
        print "|\tTTL : " + str(ttl) 
        print "|\t" + str(s_addr) + " → " + str(d_addr)
        print "|\tProtocol : " + str(protocol) 

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
             
            print "|\tTCP"
            print "|\t|\tSource Port: " + str(source_port) 
            print "|\t|\tDest Port: " + str(dest_port) 
            print "|\t|\tSequence Number: " + str(sequence) 
            print "|\t|\tAcknowledgement: " + str(acknowledgement) 
            print "|\t|\tTCP header length: " + str(tcph_length)
             
            h_size = eth_len + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            #print "|\tData : " + data
 
        elif protocol == 1 :    # ICMP
            u = iph_length + eth_len
            icmph_length = 4
            icmp_header = packet[u:u+4]
 
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print "|\tICMP"
            print "|\t|\tType: " + str(icmp_type) 
            print "|\t|\tCode: " + str(code) 
            print "|\t|\tChecksum: " + str(checksum)
             
            h_size = eth_len + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            #print "|\tData: " + data
 
        elif protocol == 17 :   # UDP
            u = iph_length + eth_len
            udph_length = 8
            udp_header = packet[u:u+8]
 
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print "|\tUDP"
            print "|\t|\tSource Port: " + str(source_port) 
            print "|\t|\tDest Port: " + str(dest_port) 
            print "|\t|\tLength: " + str(length) 
            print "|\t|\tChecksum: " + str(checksum)
             
            h_size = eth_len + iph_length + udph_length
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            #print "|\tData: " + data
 
        else :  # TODO
            print "|\tProtocolo no identificado."
    elif eth_protocol == 0x0806:     # ARP Protocol 
        arp_header = packet[eth_len:8+eth_len]
        arph = unpack('!HHBBH', arp_header)
        hw_type = {0x0001:'Ethernet', 0x0006:'IEEE 802 LAN'}[arph[0]]
        proto_type = 'IPv4' if arph[1]==0x0008 else "%.4x" % (arph[1],)

        arp_stuff = packet[8+eth_len:28+eth_len]
        arps = unpack('!6s4s6s4s', arp_stuff)
        sha = pretty_mac(arps[0])
        spa = arps[1]
        tha = pretty_mac(arps[2])
        tpa = arps[3]

        print "|\tARP"
        print "|\t|\tHW address type: " + hw_type
        print "|\t|\tProto address type: " + proto_type
        print "|\t|\tHW address length: " + str(arph[2])
        print "|\t|\tProto address length: " + str(arph[3])
        print "|\t|\tOperation: " + ("Reply" if arph[4]==2 else "Request")
        print "|\t|\tSHA: " + sha
        print "|\t|\tTHA: " + tha

def main():
    parser = argparse.ArgumentParser(description='Ejercicio de captura de paquetes de red')
    # Opción para hacer el listado de dispositivos de red
    parser.add_argument('-l', '--list-devices', dest='devices',
            action='store_const', const=devs,
            required=False, help=devs.__doc__)
    # Opción para iniciar la captura de paquetes
    parser.add_argument('--sniff', nargs=1, metavar='dispositivo', help=sniff.__doc__)

    parser.add_argument('-w', '--write-file', dest='dump', nargs=1,
            metavar='archivo-de-salida', help="Guarda la captura de paquetes a un archivo pcap.")

    parser.add_argument('--offline', nargs=1, metavar='archivo-de-lectura', help=offline.__doc__)

    args = parser.parse_args()

    if args.devices:
        args.devices()
    elif args.offline:
        offline(args.offline[0])
    elif args.sniff:
        sniff(dev=args.sniff[0], dump = args.dump[0] if args.dump else None)

if __name__ == "__main__":
    main()
