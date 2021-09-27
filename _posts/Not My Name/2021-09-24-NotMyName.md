---
layout: post
title:  "[DownUnder CTF] Not My Name"
date:   "2021-09-24"
categories: Forensics
author: isfet
image_pacchetti: /assets/posts_images/NotMyName/notmyname.pcapng-pacchetti.png
image_pacchetti-arp: /assets/posts_images/NotMyName/notmyname.pcapng-ARP.png
image_pacchetti-dns: /assets/posts_images/NotMyName/notmyname.pcapng-DNS.png
image_pacchetti-http: /assets/posts_images/NotMyName/notmyname.pcapng-HTTP.png
image_res: /assets/posts_images/NotMyName/res.txt.png
image_cyberchef: /assets/posts_images/NotMyName/cyberchef.png
---

In this challenge in DownUnder CTF 2021 only a pcap file was given.

Opening the pcap file with wireshark we can see that there are a lot of packets. There are a many different protocol.
We can see DNS query, ARP, TLS, QUIC and simple HTTP in plain text packet.
Obviously we cannot inspect the payload of TLS and QUIC packet because are encrypted.
The only packet that seems usefull for this challenge are ARP, DNS and HTTP.

<figure>
<img src="{{ page.image_pacchetti }}" alt="packets">
</figure>

There are only few HTTP packets with simple GET and POST requests, seems useless.

From this point there are only two options available:

- ARP spoofing or ARP poisoning
- Some kind of attack based on DNS packets

In the ARP packets there are not any kind of usefull information, so remains only some kind of DNS attack.

<figure>
<img src="{{ page.image_pacchetti-http }}" alt="HTTP">
</figure>

<figure>
<img src="{{ page.image_pacchetti-arp }}" alt="ARP">
</figure>

<figure>
<img src="{{ page.image_pacchetti-dns }}" alt="DNS">
</figure>

Inspecting the DNS query packet we can see something strange. Some of the packets are asking to the DNS server
strange name like the selected packet in the above image. This remind me some kind of DNS Exfiltration attack.
This attack basically use an encoded string that will be added to a normal site name. When the DNS search for this
site name decode the strings and execute the command.
So let's try something. It's time to use tshark to filter the packets.

```
tshark -r notmyname.pcapng -T fields -e dns.qry.name -Y "dns.flags.response eq 0 && ip.dst==3.24.188.205" > res.txt
```

This command get as input the pcap file and filter all the packet for DNS query response and destination ip
in whireshark syntax and export result to an output file.

<figure>
<img src="{{ page.image_res }}" alt="results.txt">
</figure>

Now it's time to decode.
Coping this on CyberChef and decoding from HEX we can obtain a lot of strings and something that seems a PNG file.
But first let see if there's something else.
And BOOM! We have the flag.

<figure>
<img src="{{ page.image_cyberchef }}" alt="CyberChef">
</figure>

```
DUCTF{c4t_g07_y0ur_n4m3}
```
