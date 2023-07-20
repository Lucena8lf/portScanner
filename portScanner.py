# coding=utf-8
#!/usr/bin/python3

# Autor: Fernando Lucena

import argparse, sys, re
from scapy.all import *

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def checkPortsTCPSYN(red, startPort, endPort, timeout, packetsInterval):
    """
    Función que checkea los puertos que se encuentran abiertos utilizando la técnica TCP SYN para
    no establecer una conexión TCP completa con el puerto.
    """
    
    # Enviamos paquete y escuchamos respuesta
    ans, unans = sr(IP(dst=red)/TCP(sport=666, dport=(startPort,endPort), flags="S"), inter=packetsInterval, timeout=timeout, verbose=False)

    # Filtramos los paquetes que nos indiquen que el puerto está abierto
    filteredPackets = [r for s,r in ans if r.sprintf("%TCP.flags%") == "SA"]
    return filteredPackets

if __name__ == '__main__':

    # Parameters
    parser = argparse.ArgumentParser() 
    parser.add_argument("IP", type=str, help="IP a la que se hará el escaneo de puertos")
    parser.add_argument("-p", "--ports", type=str, default="1-65535", required=False, help="Rango de puertos de escaneo (inicio-fin)")
    parser.add_argument("-t", "--timeout", type=int, default=1, required=False, help="Tiempo máximo de espera por una respueta (segundos)")
    parser.add_argument("-i", "--interval", type=float, default=0, required=False, help="Intervalo entre el envío de paquetes (segundos)")
    parser.add_argument("-s", "--silent", action="store_true", required=False, help="Modo silencioso, solo muestra los puertos abiertos")

    args = parser.parse_args()

    # Verificamos que haya introducido los puertos correctamente
    if not re.match(r'^\d+-\d+$', args.ports):
        print(f"{bcolors.FAIL}\n[*] ERROR: sintaxis incorrecta para el rango de puertos. Utilice el formato 'inicio-fin'.\n{bcolors.ENDC}")
        print(f"{bcolors.OKBLUE}[*] Ejemplo: python3 portScanner.py 192.168.1.1 -p 1-500 {bcolors.ENDC}")
        sys.exit(0)

    startPort, endPort = map(int, args.ports.split("-"))
    # Control de errores
    if startPort > endPort:
        print(f"{bcolors.FAIL}\n[*] ERROR: el límite inferior del rango debe ser menor o igual al límite superior. Por favor, introduzca un rango de puertos válido.{bcolors.ENDC}\n")
        print(f"{bcolors.OKBLUE}[*] Ejemplo: python3 portScanner.py 192.168.1.1 -p 1-500 {bcolors.ENDC}")
        sys.exit(0)
    

    # Comprobamos para esa IP si cada uno de los puertos están abiertos
    if not args.silent:
        print(f"{bcolors.BOLD}Iniciando escaneo en la red {args.IP} del puerto {startPort} al puerto {endPort}...{bcolors.ENDC}\n")
        
    filteredPackets = checkPortsTCPSYN(args.IP, startPort, endPort, args.timeout, args.interval)

    if args.silent:
        for packet in filteredPackets:
            print(bcolors.WARNING + "[-] " + bcolors.ENDC + bcolors.OKGREEN + packet.sprintf("%TCP.sport%") + bcolors.ENDC)
    else:
        if not filteredPackets:
            print(f"{bcolors.FAIL}[*] ¡No se ha encontrado ningún puerto abierto!{bcolors.ENDC}\n{bcolors.WARNING}[*] Verifica que la red introducida sea correcta o aumenta el rango de puertos. {bcolors.ENDC}")
        else:
            print(f"{bcolors.BOLD}Puertos abiertos:{bcolors.ENDC}")
            for packet in filteredPackets:
                print(bcolors.WARNING + "[-] " + bcolors.ENDC + bcolors.OKGREEN + packet.sprintf("%TCP.sport%") + bcolors.ENDC)
