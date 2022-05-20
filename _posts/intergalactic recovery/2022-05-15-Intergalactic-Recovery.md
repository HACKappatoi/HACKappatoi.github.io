---
layout: post
title:  "[CyberApocalypse 22] Intergalactic Recovery"
date:   "2022-05-15"
categories: Forensics
author: isfet
---

In this challenge from CyberApocalypse 22 provide only three .img file. 
I tried 'file' in cmd to check the file type and i got only 'data', so it seems that the disk images are all corrupted. From the chall description we know that are extracted from a machine, so the only idea is that they are all disk image from a raid array, but wich kind of raid? Spoiler, an hint released further will say that the are a raid 5 disk array.

Now the only problem is how to fix them in order to recovery the files. After a lot of hours spent on internet in order to understand how raid 5 works at low level i know that, given three disks, if one of them fails, the data can be recovered by the remaining disks simply xoring the data inside, but which disk is the one that is corrupted?

Inspecting the disks with an hex editor (or simply checking the file size, but we prefer longer operations right? :) ) reveal that the disk 3 is the corrupted one

![](/assets/posts_images/intergalactic_recovery/disk1.png)

![](/assets/posts_images/intergalactic_recovery/disk2.png)

![](/assets/posts_images/intergalactic_recovery/disk3.png)

Now we can try to recovery the date inside disk3 by xoring disk1 and disk2 images.

![](/assets/posts_images/intergalactic_recovery/XorFiles.png)

With the obtained disk we have to reconstruct the raid 5 array. we can do this boy mounting the 3 disks using losetup usign looback interfaces.

```
losetup /dev/loop1 disk1.img
losetup /dev/loop2 disk2.img
losetup /dev/loop3 disk3.img
```

We can use then mdadm, a tool that allow to manage disk s and in our case, to create a disk array. The hint released before, says that the oreder of disks is not necessarilly disk1, disk2 and disk3, but it can be different. So now we have to guess the order.

```
This one will give us the right disk array.
mdadm --create /dev/md1 --level=5 --raid-devices=3 /dev/loop2 /dev/loop3 /dev/loop1 
```

The last step is to mount the now disk array simply using 

```
mount /dev/md1 /mnt/chall/
```

And going to that path will give us a pdf file with the flag.

![](/assets/posts_images/intergalactic_recovery/flag.png)
