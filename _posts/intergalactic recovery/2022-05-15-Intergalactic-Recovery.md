---
layout: post
title:  "[CyberApocalypse 22] Intergalactic Recovery"
date:   "2022-05-15"
categories: Forensics
author: isfet
image_pacchetti: /assets/posts_images/IFTPP/pacchetti.png
image_rfc: /assets/posts_images/IFTPP/rfc.png
image_chiavi: /assets/posts_images/IFTPP/chiavi.png
image_flag: /assets/posts_images/IFTPP/lol.jfif
---

In this challenge from CyberApocalypse 22 provide only three .img file. 
I tried 'file' in cmd to check the file type and i got only 'data', so it seems that the disk images are all corrupted. From the chall description we know that are extracted from a machine, so the only idea is that they are all disk image from a raid array, but wich kind of raid? Spoiler, an hint released further will say that the are a raid 5 disk array.

Now the only problem is how to fix them in order to recovery the files. After a lot of hours spent on internet in order to understand how raid 5 works at low level i know that, given three disks, if one of them fails, the data can be recovered by the remaining disks simply xoring the data inside, but which disk is the one that is corrupted?

Inspecting the disks with an hex editor (or simply checking the file size, but we prefer longer operations right? :) ) reveal that the disk 3 is the corrupted one



<figure>
<img src="{{ page.image_pacchetti }}" alt="pacchetti">
</figure>
<figure>
<img src="{{ page.image_rfc }}" alt="rfc">
</figure>


Following the RFC we can figure out that:

- The first ICMP packet is the client request to establish the comunication and the second the ACK from the server
- The third ICMP packet is the client key (we will discuss this further)
- The forth ICMP packet is the server key (we will discuss this further)
- The other packets are alternating chunk of the request file and the ACK from the client that check the checksum value (we only have to know that this checksum is 8 bit long)

Well, now we know how the comunication bewteen this two hosts works. The RFC says that all file chunks are encrypted with a shared key.
The shared key is generated as fallow:
- We have to append the client key to the server key (both 16 bit)
- We have to sort the obtined key in descending order
- We have to compute the sha1 of this key and the encode in base64 the results

The ecnrypted message is obtained by simply xoring the plain base64 file chunk with the resulted key (not shared between the host, but computed "in loco" on the machine)

The RFC also give us a golang implementation of the function that comput the shared key. The only thing to do now is to retrieve both the server and client random 16 bit key from the ICMP packet.
Paying more attention on all the packets we can see that all starts with the same bits and after 16 bits (our key) have the same bit again (our checksum)

<figure>
<img src="{{ page.image_chiavi }}" alt="chiavi">
</figure>

With the fallowing simple golang script we can comput the shared key:

```
package main

import (
    "crypto/sha1"
    "fmt"
    "encoding/base64"
    "sort"
)


func calcSharedKey(key1 []byte, key2 []byte) []byte {
        combined := append(key1, key2...) // put two keys together
        sort.Slice(combined, func(i int, j int) bool {
            return combined[i] > combined[j]
            }) // sort descending
        hasher := sha1.New()
        hasher.Write(combined)
        sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
        return []byte(sha)
}

func main() {

    var key1 = []byte{0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d, 0x72, 0x95, 0x66, 0xc7, 0x4d, 0x10, 0x03, 0x7c} 
    var key2 = []byte{0x52, 0xfd, 0xfc, 0x07, 0x21, 0x82, 0x65, 0x4f, 0x16, 0x3f, 0x5f, 0x0f, 0x9a, 0x62, 0x1d, 0x72}

    var key = calcSharedKey(key2, key1)
    fmt.Println(string(key))

}
```

Now, from the pcap file, we know that the client has requested a jpg file from the server, so we have find after the first chunk decryption the jpg header. After that, it's time to decode all file chunks and put all together and boom! we have the image with the flag.

<figure>
<img src="{{ page.image_flag }}" alt="flag">
</figure>
