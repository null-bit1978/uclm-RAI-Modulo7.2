import whois
import argparse
import socket
import sys
import re
import nmap
import dns.resolver

def Main():
    # parseamos las opciones y argumentos. El único argumento obligatorio es la de host. La opción de --nmap se usa para cumplir con el punto 2 de la práctica
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="The host to be recon", type=str)
    parser.add_argument("--nmap", help="Activates an nmap scan", action="store_true")
    args = parser.parse_args()

    ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") # necesitamos identificar si el usuario ha introducido una dirección o un dominio

    #las funciones que hacen todo el trabajo
    def whois_query(host):
        return whois.query(host).__dict__

    def get_dns_servers(dict_query):
        return dict_query["name_servers"]

    def get_dns_info(reg):
        reg_dict = {}
        res = dns.resolver.resolve(host, reg)
        reg_dict[reg] = res.__dict__["rrset"]
        return reg_dict

    def nmap_scan(host):
        nm = nmap.PortScanner()
        nm.scan(hosts=host, arguments="--top-ports 1000 -sV -T4")
        return nm[host]['tcp'].items()

    # para poder hacer consultas whois
    if re.match(ip_pattern, args.host):
        try:
            host = socket.gethostbyaddr(args.host)[0]
        except socket.gaierror:
            print("No hay un host asociado a la IP introducida, pruebe con otra dirección diferente")
            sys.exit(1)
        except socket.herror:
            print("El host introducido es desconocido")
            host = args.host
        try:
            result = whois_query(host)
        except whois.exceptions.UnknownTld:
            print("No hay registros whois para el TLD solicitado")
    else:
        host = args.host
        try:
            result = whois_query(host)
            print("---------------------------------")
            print(f"The name servers for {host} are:")
            for ns in get_dns_servers(result):
                print(ns)
        except whois.exceptions.UnknownTld:
            print("No hay registros whois para el TLD solicitado")
        try:
            regs = ["A", "NS", "MX", "CNAME", "TXT"]
            dns_info = map(get_dns_info, regs)
            print("---------------------------------")
            print(f"The DNS info for {host} is:")
            for elem in dns_info:
                print(elem)
        except:
            print(f"Couldn't get the info requested for this register")

    if args.nmap:
        host = socket.gethostbyname(args.host)
        print("-------------------------------------")
        print("Scanning the top 1000 ports with nmap, please wait...")
        ports = nmap_scan(host)
        print(f"Scan results for ")
        for port, value in ports:
            print(str(port) + ": " + value['state'] + " " + value['product'] + " " + value['version'])






if __name__ == "__main__":
    Main()

