#!/usr/bin/python3
#WHOIS LOOKUP
#Author: dynos01 <i@dyn.im>
import socket
import sys
import socket

def suffix_lookup(suffix):
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s1.connect(('whois.iana.org', 43))
    s1.send((suffix + '\r\n').encode())
    r1 = b''
    while True:
        d1 = s1.recv(4096)
        r1 += d1
        if not d1:
            break
    s1.close()
    if not 'whois:' in r1.decode():
        return('no_whois')
    else:
        return(r1.decode().split('whois:')[1].split(' ')[8].split('\n')[0])

def domain_lookup(domain,server):
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.connect((server, 43))
    s2.send((domain + '\r\n').encode())
    r2 = b''
    while True:
        d2 = s2.recv(4096)
        r2 += d2
        if not d2:
            break
    s2.close()
    return(r2.decode().replace('\r',''))

def cno():
    global domain
    domain = '=' + domain
    return(domain_lookup(domain,suffix_lookup(suffix)).split('Whois Server: ')[-1].split(' ')[0].replace('\n',''))
    
domain = sys.argv[1]
suffix = domain.split('.')[-1]
if suffix in {'com','net','org'}:
    server = cno()
else:
    server = suffix_lookup(suffix)
if suffix_lookup(suffix) == 'no_whois':
    print("The suffix you entered doesn't have a WHOIS server set. Stopping.")
else:
    print(domain_lookup(domain,server)[:-1])   
