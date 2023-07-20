# Port Scanner

Script de Python que realiza un escaneo de puertos en una IP de red especificada. El escaneo se realiza utilizando la técnica TCP SYN para lo cual se ayuda de la herramienta Scapy.

## Técnica TCP SYN
Este script utiliza la técnica TCP SYN para escanear los puertos de una IP de red. El escaneo TCP SYN consiste en enviar paquetes SYN a cada puerto y esperar una respuesta SYN-ACK. Si se recibe un SYN-ACK, se considera que el puerto está abierto.

Por lo tanto, con esta técnica no es necesario establecer una conexión TCP completa con el puerto para detectar si está abierto o no.

## Requisitos
- Python 3.x
- Scapy

## Instalación y uso
1. En primer lugar debemos clonar el proyecto o descargar el código fuente:
```sh
git clone https://github.com/Lucena8lf/portScanner.git
```
2. Verificamos que tenemos instalado tanto Python 3.x como Scapy. En caso de no tener Scapy podemos instalarlo con:
```sh
pip install scapy
```
3. Ejecutamos el script `portScanner.py` (Importante ejecutar como root para evitar problemas durante el escaneo):
```sh
sudo python3 portScanner.py <IP> [-p PORTS] [-t TIMEOUT] [-i INTERVAL]
```
 - `IP`: especifica la dirección IP de la red que se desea escanear.
 - `PORTS` (opcional): especifica el rango de puertos a escanear en formato "inicio-fin". Si no se proporciona, se hará un escaneo de puertos completo, es decir, con un rango 1-65535.
 - `TIMEOUT` (opcional): especifica el tiempo máximo de espera por respuesta en segundos.
 - `INTEVAL` (opcional): especifica el intervalo entre envío de paquetes en segundos.

Ejemplos:
sudo python3 portScanner.py 192.168.0.1
sudo python3 portScanner.py 10.0.0.1 -p 100-5000 -t 5 -i 1

## Mejoras a implementar
- Implementación de opciones de escaneo adicionales como escaneo UDP o escaneo TCP Connect.
- Implementación de concurrencia para realizar escaneos simultáneos en múltiples puertos y poder tener un tiempo de ejecución más rápido.

