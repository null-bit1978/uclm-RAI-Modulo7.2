import whois
import argparse
import socket
import sys
import re
import nmap
import dns.resolver
import requests
from shodan import Shodan

def Main():
    IS_HTTP = False # esta variable la utilizamos luego para analizar la parte de servidor web
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

    def shodan_scan(host):
        key = "TMOFqYjmOcTWqhFSGZ2qIA4Xo72hZxfX"
        engine = Shodan(key)
        return engine.host(host)

    def options_request(host):
        verbs = requests.options(host)
        return verbs.headers

    # para poder compaginar toda la funcionalidad del script, necesitamos uniformizar el formato del host, por lo que verificamos, con ayuda de nuestro patrón,
    # si hemos recibido una dirección IP o un nombre de dominio
    if re.match(ip_pattern, args.host):
        try:
            host = socket.gethostbyaddr(args.host)[0]
        except socket.gaierror:
            print("No hay un host asociado a la IP introducida, pruebe con otra dirección diferente")
            sys.exit(1)
        except socket.herror:
            print("El host introducido es desconocido")
            host = args.host
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
        regs = ["A", "NS", "MX", "AAAA", "TXT"]
        dns_info = map(get_dns_info, regs) # usamos map para pasar todos los valores de la lista a nuestra función y evitarnos escribir más código
        print("---------------------------------")
        print(f"The DNS info for {host} is:")
        for elem in dns_info:
            print(elem)
    except:
        print(f"Couldn't get the info requested for this register.")

    # chequeamos si la flag de nmap está activada
    if args.nmap:
        host = socket.gethostbyname(args.host)
        print("-------------------------------------")
        print("Scanning the top 1000 ports with nmap, please wait...")
        ports = nmap_scan(host)
        print(f"Scan results for {host}:")
        for port, value in ports:
            print(str(port) + ": " + value['state'] + " " + value['product'] + " " + value['version'])

        print("-------------------------------------")
        print("Scanning the host with shodan, please wait...")

        shodan_info = shodan_scan(host)
        www_ports = [80, 8080, 443]
        for k, v in shodan_info.items():
            print(str(k) + ": " +str(v))
        shodan_ports = shodan_info['ports']
        for port in shodan_ports:
            if port in www_ports:
                IS_HTTP = True
        if IS_HTTP:
            try:
                print("------------------------------------")
                headers = options_request("http://" + host)
                print("The HTTP methods allow for this host are:")
                print(headers['allow'])
            except KeyError:
                print("The server didn't return the 'allow' header")
                print("These are the headers returned by the server:")
                print(headers)

        else:
            print("The host is not an HTTP server.")


if __name__ == "__main__":
    Main()

