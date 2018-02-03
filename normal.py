import sys
import getopt
import time
from os import popen
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sendp, IP, UDP, Ether, TCP
from random import randrange
from random import randint
import random
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
    end = 5
    ip = ".".join([str(first),str(second),str(third),str(randrange(start,end))])
   # print start
   # print end
    return ip

def genTraffic():
    m =0
    a = randint(1,8)
    interface = popen('ifconfig | awk \'/eth0/ {print $1}\'').read()
    #for i in xrange(5000):
    payload = " Hello world "
    packets = Ether()/IP(dst=gendest(),src=sourceIPgen())/UDP(dport=80,sport=2)/payload
    print(repr(packets))
    while m<=a:
       sendp(packets,iface=interface.rstrip(),inter=0.1)
       m+=1     
    
def main():
       #run_event = threading.Event()
       #run_event.set()
       #d1 = 0.1 
       timeout = time.time() + 60*10
       #threading.Timer(0.1,genTraffic).start()
       while True:
         genTraffic()
         if time.time()>timeout:
            break

   
        
if __name__ == '__main__':
  main()



