import sys
import getopt
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange
import threading


def sourceIPgen():
    not_valid = [10,127,254,1,2,169,172,192]

    first = randrange(1,256)

    while first in not_valid:
        first = randrange(1,256)

    ip = ".".join([str(first),str(randrange(1,256)),str(randrange(1,256)),str(randrange(1,256))])

    return ip


def gendest():

    first = 10
    second =0; third =0;
    start = 2
    end = 60
    ip = ".".join([str(first),str(second),str(third),str(randrange(start,end))])
    return ip

def genTraffic(delay, run_event):
    
    while run_event.is_set():
        time.sleep(delay)

        interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()

        for i in xrange(500):
           packets = Ether()/IP(dst=gendest(),src=sourceIPgen())/UDP(dport=80,sport=2)
           print(repr(packets))
          
           sendp( packets,iface=interface.rstrip(),inter=0.2)
           if i==499:
              sys.exit()
    
def main():
   
    run_event = threading.Event()
    run_event.set()
    d1 = 0.1
    t1 = threading.Thread(target = genTraffic, args = (d1,run_event))

    d2 = 0.5
    t2 = threading.Thread(target = genTraffic, args = (d2,run_event))

    t1.start()
    time.sleep(2)
    t2.start()

    try:
        while 1:
            time.sleep(2)
    except KeyboardInterrupt:
        print "attempting to close threads. Max wait =",max(d1,d2)
        run_event.clear()
        t1.join()
        t2.join()
        print "threads successfully closed"

        
if __name__ == '__main__':
  main()



