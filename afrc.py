#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse, pcapy, socket, sys, datetime
from struct import unpack
from sys import exit

def devs():
    """ Muestra las interfaces de red disponibles."""

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
    eth_protocol = socket.ntohs(eth[2])

    print 'MAC destino: ' + pretty_mac(packet[0:6]) + ' MAC origen: ' + pretty_mac(packet[6:12]) + ' Protocolo: ' + str(eth_protocol)

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
