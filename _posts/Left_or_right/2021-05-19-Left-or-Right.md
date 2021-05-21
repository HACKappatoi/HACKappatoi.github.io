--- 
layout: post 
title:  "[m0lecon 2021] Left or Right"
date: "2021-05-19" 
categories: MISC 
author: lvcivn
---

My first idea was to use itertools and calculate te minimum leftmost point for every possible combination but this solution was obvioslly to slow so i ended up with another idea.
My final solution can be divided in three main steps:
1. **Cleaning**
1. **Sorting**
2. **Calculate the distance**

### Cleaning
I noticed that in every string i recive, for example **RLRLRRRLL**, his leftmost point is **0** because we never go left more than the starting point, when we go **RL**, we remain in the same place so we can replace recursively alle the **RL** from each string with an **empty string**
 ( **RLRLRRRLL** in the end becomes just **R**  and **LRLL** will be **LL**).
Our final string will have every time the format
``` 'L'*n + 'R'*m  ```

```python
  for string in inputArray:
        n=string.replace('RL','')
        x=string
        while x!=n:
            x=n
            n=n.replace('RL','')
        if n!='':
            newArray.append(n)
```
### Sorting
After cleaning my array i just sort it by the **percentage of L in each string** , this is were the *"magic"* happens
```python
newArray.sort(key = lambda x: (x.count('L')/len(x))*100000 )
```
 **higher the percentage of L in the string, higher will be the index of the string into the new array**, in this way we have at the beginning elements that are just R, then we have R and L (higher the index of the array, lower the percentage of **R** in each string) and in the end we have the strings with just **L**
```['LLLLLLLLRRRRR', 'LR', 'RRRRRRRRRRRR', 'LLLLLL'] ```
sorted will become
 ```['RRRRRRRRRRRR', 'LR', 'LLLLLLLLRRRRR', 'LLLLLL']```
the result of the sort is the ***combination of strings with lower leftmost value** because we are going as right as possible to avoid the **L** strings.
### Calculate the distance
Once we have the sorted array in the correct order the last thing we have to do is to make a string from it and calculate the leftmost point from 0, our start point.
Each **R i increments by 1, each L i decrements by 1**, our final solution will be 0 or a negative number so we will send the absolute value of our distance.
```python
    position=0
    distance=0
    for c in ''.join(newArray):
        position= position+1 if c=='R' else position-1
        distance=distance if position>distance else position

    p.sendline(str(abs(distance)))
```
# Final script
```python
from hashlib import *
from pwn import *
import time


p=remote("challs.m0lecon.it",5886)
res=p.recv()
ar=str(res).replace('.\\n\'','').split(' ')

#solving the Proof of Work
h=''
d=''
while(d=='' or h[-5::]!=ar[13]):
    d=ar[6]+str(random.randrange(1, 0xffffffffffffffffffffffff))
    h=hashlib.sha256(d.encode()).hexdigest()
print(d,h)
time.sleep(1)
p.sendline(d)
time.sleep(1)
log.info(p.recvuntil('each test.\n'))
p.sendline()


for i in range (200):

    #Number of inputs
    numeroDiInp=int(p.recvline().decode('utf-8'))

    #Get the MOFO strings
    inputArray=[]
    for t in range(numeroDiInp):
        inputArray.append(p.recvline().decode('utf-8').strip())

    #Cleaning
    newArray=[]
    for string in inputArray:
        n=string.replace('RL','')
        x=string
        while x!=n:
            x=n
            n=n.replace('RL','')
        if n!='':
            newArray.append(n)

    #Sorting
    newArray.sort(key = lambda x: (x.count('L')/len(x))*100000 )

    #Calculate the distance
    position=0
    distance=0
    for c in ''.join(newArray):
        position= position+1 if c=='R' else position-1
        distance=distance if position>distance else position

    #Send the solution
    p.sendline(str(abs(distance)))
    print(i,') ',distance,p.recvline().decode('utf-8'))

print('flag:',p.recvline().decode('utf-8'))
```
# flag: b'ptm{45_r16h7_45_p0551bl3}'
