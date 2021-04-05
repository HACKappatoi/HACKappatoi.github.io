---
layout: post
title:  "[Shakti CTF] Help Me"
date:   "2021-04-04"
categories: Forensics
author: isfet
---

This challenge of **ShaktiCon** worth 400pts. In this challenge only a file was given. After downloaded it i saw that has a particular extension that i've never saw. It was a .vmem file. After googling a while i found that is a particular file that exists only on startup and crash state of a virtual machine and is a mapping of the memory of the guest machine. The problem still was how to open and read it. We can do this in two ways:
- With an hex editor, but in this way you have to read the entire memory dump
- With a tool that analyze and extract different information from it (volatility)

With volatility we can navigate the entire memory dump and use different tools available in this suite to extract information.
First of all we have to know more about the image info. Running the fallowing command will return the fallowing output
```
volatility_2.6_win64_standalone.exe imageinfo -f ..\..\Challenge.vmem
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (C:\Users\dinam\Downloads\Challenge.vmem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf80002a100a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002a11d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2021-04-03 05:10:52 UTC+0000
     Image local date and time : 2021-04-03 10:40:52 +0530
```

So the image is of a Windows7 machine.
Volatile suite offers diffent tools in order to extract more information from .vmem file.
One of this is the "*consoles*" command, that pull out cmd line history. Running this command we have obtained the fallowing output:

```
volatility_2.6_win64_standalone.exe -f ..\..\Challenge.vmem --profile=Win7SP1x64 consoles
Volatility Foundation Volatility Framework 2.6
**************************************************
ConsoleProcess: conhost.exe Pid: 1144
Console: 0xff716200 CommandHistorySize: 50
HistoryBufferCount: 1 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: C:\Windows\system32\cmd.exe
AttachedProcess: cmd.exe Pid: 1708 Handle: 0x60
----
CommandHistory: 0x26e9c0 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 1 LastAdded: 0 LastDisplayed: 0
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x60
Cmd #0 at 0x2478b0: UGFydCAxlC0gc2hha3RpY3Rme0gwcDM=
----
Screen 0x250f70 X:80 Y:300
Dump:
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\alexander>UGFydCAxlC0gc2hha3RpY3Rme0gwcDM=
'UGFydCAxlC0gc2hha3RpY3Rme0gwcDM' is not recognized as an internal or external c
ommand,
operable program or batch file.

C:\Users\alexander>
```

With more attention we can see a strange command in the history: "*UGFydCAxlC0gc2hha3RpY3Rme0gwcDM=*". This seems like a base64 string. Converting this in a more simple format give us the first part of the flag: "*shaktictf{H0p3*".

At this point we have a lot of different command to run on the image, but reading the description of teh challenge we know that we have to extract file from the .vmem file to achive the other part of the flag.
We tried to extract the search history from Internet Explorer, maybe there we can find more usefull information.
The command try to reconstract history from saved coockies, but unfortunatelly, we have obtained no usefull information. So we have decided to do this manally. We can list all file on the machine and reading a bit the result obtained we can find the ie history:
```
...
\Device\HarddiskVolume1\Windows\System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\prnep003.cat
\Device\HarddiskVolume1\Windows\System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\prnep00a.cat
\Device\HarddiskVolume1\Windows\System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\prnca00z.cat
\Device\HarddiskVolume1\Windows\System32\catroot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\prnca00y.cat
\Device\HarddiskVolume1\Program Files\desktop.ini
\Device\HarddiskVolume1\Users\alexander\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\WinRAR\WinRAR.lnk
**\Device\HarddiskVolume1\Users\alexander\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\index.dat**
\Device\HarddiskVolume1\Users\alexander\AppData\Roaming\Microsoft\Windows\Cookies\index.dat
\Device\HarddiskVolume1\Users\alexander\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat
\Device\HarddiskVolume1\$Directory
\Device\HarddiskVolume1\$Directory
\Device\HarddiskVolume1\$Directory
\Device\HarddiskVolume1\Windows\System32\drivers\tdx.sys
\Device\HarddiskVolume1\Windows\System32\drivers\tdi.sys
...
```
Boom! This file contains the information that we are searching for! We can download it running the fallowing command:
**volatility_2.6_win64_standalone.exe -f ..\..\Challenge.vmem --profile=Win7SP1x64 dumpfile <address if the file> --name <outputfilename> -D <destinationdir>**

The downloaded file contains usefull strings:
**Visited: alexander@file:///C:/Users/alexander/Downloads/L4ST.py**
**Visited: alexander@file:///C:/Users/alexander/Documents/Part%20II.png**
Now we know that we have to find this two files in the memory. Running again the previous command we can download this file.
The first one is a python code that we have to use to obtain the last part of the flag, the otherone it's image.
So... it's stego time!
Opening this image with stegsolve, on some layer, there something strange that seems like a LSB. Opening with an online to for LSB we can obtain the second part of the flag: **_y0U_l1k3d_**.
Now it's time to read the python code:
```python
s=4
y=[]
Z=[]
k=[]
Q='uh27bio:uY<xrA.'

def yes(inp):

    st=[]
    for i in range (len(inp)):
        st.append(chr(ord(inp[i])-i+4))
    print(''.join(st)+"}")

def Checkin(inp):

    for i in range(len(inp)):
        if(len(inp)<=7):
            Z.append(chr(ord(inp[i])-1+i))
        else:
            Z.append(chr(ord(inp[i])+4))
    return(''.join(Z))

def tryin(text,s):

    result = ''
    for i in range(len(text)):     	
        char = text[i]
        if(char.isnumeric()):
            result+=(chr(ord(char)-1))
        elif(char.isupper()):
            result += chr((ord(char) + s-65) % 26 + 65)
        else:
            result+=(chr(ord(char)^1))
    return result 
    
X=input('Enter input:  ')
k=Checkin(tryin(X,s))
print(k)
if(Q==k):
    print('Yoo.. looks like your flag is complete!!')
    yes(X)
else:
    print('try again:/ ')
```

Seems like that this code apply some operation on the flag and only if the input is equal to the given string in the code it will return the last part. So we have to put some string that will be equal to "**Q**" and we have to reverse the operation to obtain the last part.
To reverse the operation we have also to call the functions in reverse order
```python
#from this
k=Checkin(tryin(X,s))
#to this
k=tryin(Checkin(X),s)
```
We have also to pass in input the string Q and reverse all the operation in all the function
So let's arm ourselves with patience and after a while with also paper and pen ( :( ) we have obtained the las part of the flag: "**ch4lL3ng3!}**"

The complete flag is: "**shaktictf{H0p3_y0U_l1k3d_ch4lL3ng3!}**"