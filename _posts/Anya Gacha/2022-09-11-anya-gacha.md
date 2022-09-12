---
layout: post
title: "[CSAW] Anya Gacha"
date:   "2022-09-11"
categories: Reverse
author: "Retro"
---
This has been the first CTF challenge that involved a little GamePwn that I've ever found. Will I be able to find the rare character Anya and her flag?
In this challenge you can choose to download the game based on your platform: in my case it is Windows. The game is based on Unity.
The first thing I've tried has been opening the game: it shows us a static image with the possibility to execute an action, to make a wish: 

![](/assets/posts_images/anyagacha/1-image1.png)

Let's resume the first information available:
- We start with 100 credits;
- We can make a wish for 10 credits;
- We have the 0.1% chance to get the flag;
- **The flag is guaranteed with 1000 wishes**

If we click on the button we pay 10 credits to get this image:
![](/assets/posts_images/anyagacha/2-image2.png)
Well, bad luck!

The first step into reversing the game is opening it with DNSpy. It is based on unity so the target file is stored into "AnyaGacha_Data\Managed\Assembly-CSharp.dll". Any important information will be stored here. We're interested in the content of the module "Gacha". The first function to analyse is "start":
![](/assets/posts_images/anyagacha/3-start.png)
Here we have a counter, a value, and a value obfuscator. The curious thing is that the counter is initialized to the string "wakuwaku".  Well, let's  ignore the logs and search for other interesting modules.
![](/assets/posts_images/anyagacha/4-wish.png)
This is the logic behind the wish action: here we acknowledge that the value that has been defined before is the credits counter. We don't need it at the moment. But on the counter we've initialized before is now applied the SHA256 hashing algorithm... OK, let's continue and see what is  the routine Upload:
![](/assets/posts_images/anyagacha/5-update.png)

Oh it's clearer now. The flag is requested to a server to which a post request containing the counter hash converted to base64 is sent: if the response content is empty we've failed, else we will get our flag.

Now  we can be more precise on how to solve this challenge; in particular we've three paths we can follow:
- We can automate this in python so i can compute the 1000 hashes and analyze the response;
- Hardcode the expected data to send, so I can get the answer in game;
- We can edit the credits in order to reach 10000 and have the posibility to make 1000 wishes... Too slow

Let's ignore the 3rd path and follow the first one at the moment. This is the script I've created to solve the challenge:

```python
import hashlib
from base64 import b64encode
import requests

counter=b"wakuwaku"
server="http://rev.chal.csaw.io:10010"

for i in range(1000):
    m=hashlib.sha256()
    m.update(counter)
    counter=m.digest()

d={"data": b64encode(counter)}
h={'Content-Type': 'application/x-www-form-urlencoded'}
print(d)
print(f"flag{requests.post(server, data=d, headers=h).content.decode()}")
```

We've just imported the hashlib and base64 module to encrypt the counter, and requests to actually perform the requests:
I've then declared the counter as bytes (as I've seen on DNSpy), and the server, that was present in the analysed  file as a string.
I've then computed and updated the counter 1000 times. This has been my first attempt, I've imagined that the CTF organizers would never appreciate getting 1000 requests from each player at a time. That would have been the next tentative.
Let's send the counter data as a base64 encoded string, in the post request; the content type has been defined as application/x-www-form-urlencoded after I've analysed the packets with Wireshark. 

Let's execute this script:
![](/assets/posts_images/anyagacha/6-flag.png)
Well done! That was correct.

Let's try now the alternative method and hardcode the data for the post request. I've just modified my script to get the 1000th computed hash and rightclicked on the Update module to edit it:
![](/assets/posts_images/anyagacha/7-module.png)
**REMEMBER TO SAVE ALL THE EDITS AFTER COMPILING THE MODULE**
Now the payload of the request will be always the same. 

Let's make a wish now:
![](/assets/posts_images/anyagacha/8-flagalt.png)
Well done again!

Finally, our flag is: 
*flag{@nya_haha_1nakute_5amishii}*
