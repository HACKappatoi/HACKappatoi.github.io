---
layout: post
title:  "Grocery List"
date:   "2021-04-04"
categories: MISC
author: lvcivn
---

In this 200 points challenge from **ShaktiCon** we get a txt with a base64 string: 
```
UmV2ZXJzZSBHcm9jZXJ5UGxhY2UKCnZpY2h5c3NvaXNlICAgICAgICAgICAgIAptYW5nbyAgICAgICAgICAgICAgICAgICAKdmVybW91dGgKenVjb3R0bwpzYW5kd2ljaApsYW1iCnZlYWwKeW9ndXJ0CnZlcm1pY2VsbGkKenVjY2hpbmkKc2FsbW9uCmZlbm5lbCBzZWVkcwppY2UgY3JlYW0KY2Fycm90cwp1bmFnaQppbmNhIGJlcnJpZXMKY2FiYmFnZQp1cG1hCmdyYXBlcwpuYWFuCmFwcGxlcwpiYW5hbmFzCmFsbW9uZHMKYmFzaWwKZmVudWdyZWVrCnBvdGF0b2VzCnBpZQpzb3kgYmVhbnMKZWdncwp0dW5hZmlzaAoKRmluZCB0aGUgaW5wdXQgdG8gdGhlIGZvbGxvd2luZyBvdXRwdXQuCk9VVFBVVDogNGN1bTc3aXRRZEt5NHI3Y35ybTV1MDVwbE4=
```
with a **base64** decoder we get this "*Grocery List*":
```
Reverse GroceryPlace

vichyssoise             
mango                   
vermouth
zucotto
sandwich
lamb
veal
yogurt
vermicelli
zucchini
salmon
fennel seeds
ice cream
carrots
unagi
inca berries
cabbage
upma
grapes
naan
apples
bananas
almonds
basil
fenugreek
potatoes
pie
soy beans
eggs
tunafish

Find the input to the following output.
OUTPUT: 4cum77itQdKy4r7c~rm5u05plN
```
The last two lines tell us what to do so..
after some *osint*, I found an ***esoteric programming language*** and his stack instructions are described by the first letter of each "product" on the list but I was not able to find any compiler or interpreter for it so i had to decode it by hand 🙃.
Online there are 2 sources that explains what every instrunction does: [esolang.org](https://esolangs.org/wiki/Grocery_List) and [progopedia.com](http://progopedia.com/language/grocery-list/ ).
I tried to translate my list with the [esolang table](https://esolangs.org/wiki/Grocery_List) but when i saw the **A instruction**
```
a	pops the top two values on the stack, adds them together and pops the result.
```
It made no sense to ***"pop the result"*** so i tried to translate the code with [progopedia table](http://progopedia.com/language/grocery-list/ ).
```
a (add) — push S0+S1.
b (bring) — remove bottom element and push it on the top.
c (copy) — duplicate S0.
d (divide) — push S0/S1.
e (end loop) — end of the loop.
f (flip) — flip elements S0 and S1.
g (greater than) — push 1, if S0>S1, and 0 otherwise.
h — execute command which corresponds to character a+S0%26.
i (input) — read a character from stdin and push its ASCII value.
j (jump) — jump S0 lines forward.
k (kill) — remove all elements from the stack.
l (loop) — start loop: the loop repeats as long as S0is non-zero and there are elements in the stack.
m (multiply) — push S0*S1.
n (number) — push the number of characters in the current list item (including whitespace).
o (output) — print S0 as a number.
p (print) — print S0 as a character.
q — no operation.
r (remainder) — push S0 mod S1.
s (subtract) — push S0-S1.
t (terminate) — terminate program execution.
u (unbring) — pop S0 and put it to the bottom of the stack.
v (value) — push ASCII-code of the next list item (and skip execution of the next line).
w — push 100.
x — pop S0.
y — remove Sn, where n is the number of characters in the current list item.
z (zero) — push 1 if S0=0, and 0 otherwise.
```
> PS1: `The "v" instructions push only the first letter from the word`


This is my "Translation" of the program:
```
vichyssoise             
mango                                                                stack:  m     
vermouth
zucotto		                                                        stack:  zm
sandwich	                                                        stack:  (z-m)
lamb		    while (z-m)!=0:                                     stack:  (z-m)
veal		      
yogurt			                                                    stack:  y(z-m)
vermicelli
zucchini		                                                    stack:  zy(z-m)
salmon			                                                    stack:  (z-y)(z-m)		
fennel seeds		                                                stack:  (z-m)(z-y)
ice cream		$ will be mi first input                            stack:  $(z-m)(z-y)
carrots			                                                    stack:  $$(z-m)(z-y)
unagi			                                                    stack:  $(z-m)(z-y)$
inca berries	# will be my second input                           stack:  #$(z-m)(z-y)$
cabbage			                                                    stack:  ##$(z-m)(z-y)$
upma			                                                    stack:  #$(z-m)(z-y)$#
grapes			1#$(z-m)(z-y)$# if #>$ else 0#$(z-m)(z-y)$#         
                ? will be 1 or 0, from the condition below          stack:  ?#$(z-m)(z-y)$#
naan			                                                    stack:  4?#$(z-m)(z-y)$#
apples			                                                    stack:  (4+?)#$(z-m)(z-y)$#
bananas			                                                    stack:  #(4+?)#$(z-m)(z-y)$
almonds			                                                    stack:  (#+4+?)#$(z-m)(z-y)$
basil			                                                    stack:  $(#+4+?)#$(z-m)(z-y)
fenugreek		                                                    stack:  (#+4+?)$#$(z-m)(z-y)
potatoes		print((#+4+?))                                      stack:  $#$(z-m)(z-y)
pie		    	print($)                                            stack:  #$(m-z)(z-y)
soy beans	    ends the cicle if (#-$)==0	                        stack:  (#-$)(m-z)(z-y)
eggs			
tunafish        terminates the program
```
after that, i translated it line by line into a python script:
```
st=[]
st.insert(0,ord('m'))
st.insert(0,ord('z'))
st[0]-=st.pop(1)
def inverti(primo,secondo):
    temp1=st[primo]
    temp2=st[secondo]
    st[primo]=temp2
    st[secondo]=temp1

while(st[0]!=0):
    st.insert(0,ord('y'))
    st.insert(0,ord('z'))
    st[0]-=st.pop(1)
    inverti(0,1)
    pri=input('first input: ')
    st.insert(0,ord(pri))
    st.append(ord(pri))
    seco=input('second input: ')
    st.insert(0,ord(seco))
    st.append(ord(seco))
    st.insert(0,1) if(st[0]>st[1]) else st.insert(0,0)
    st.insert(0,4)
    st[0]+=st.pop(1) #apples
    st.insert(0,st.pop(len(st)-1))
    st[0]+=st.pop(1)
    st.insert(0,st.pop(len(st)-1))
    inverti(0,1)
    print(chr(st.pop(0)))
    print(chr(st.pop(0)))
    st[0]-=st.pop(1)
```
As we see, the output of the program depense only by our inputs so we can simplify our script into this function
```
def getRes(a,b):
    firstPrint=1 if ord(b)>ord(a) else 0
    firstPrint+=4
    firstPrint+=ord(b)
    return chr(firstPrint)+a
```
And this function will encrypt 2 letters per time, now that we have a simple and working function, we can bruteforce the inputs and try to get the solution.
```
dic="1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
target="4cum77itQdKy4r7c~rm5u05plN"
result=""
while len(target)!= len(result):
    coupleAim=target[0+len(result):2+len(result)]
    for a in dic:
        for b in dic:
            if(getRes(a,b)==coupleAim):
                result+=a
                result+=b
print(result)
>   c0mp73tedMyGr0c3ry5h0pp1Ng
```
That's our FLAG! We now can add shaktictf{} and we get:
**shaktictf{c0mp73tedMyGr0c3ry5h0pp1Ng}**