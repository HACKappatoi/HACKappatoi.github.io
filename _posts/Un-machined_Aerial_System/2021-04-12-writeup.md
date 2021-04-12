---
layout: post
title:  "[RITSEC CTF 21] Un-machined Aerial System"
date:   "2021-04-12"
categories: Reverse
author: eurus
---

we have an elf file. By disassembling it we have that:

```assembly
.text:18C2     lea     rdi, format     ; "Fill in the rest of the flag: RS{"
.text:18C9     mov     eax, 0
.text:18CE     call    _printf
.text:18D3     mov     rdx, cs:stdin   ; stream
.text:18DA     lea     rax, [rbp+s]
.text:18DE     mov     esi, 14h        ; n
.text:18E3     mov     rdi, rax        ; s
.text:18E6     call    _fgets
.text:18EB     lea     rax, [rbp+s]
.text:18EF     lea     rsi, reject     ; "\n"
.text:18F6     mov     rdi, rax        ; s
.text:18F9     call    _strcspn
.text:18FE     mov     [rbp+rax+s], 0
.text:1903     lea     rax, [rbp+s]
.text:1907     mov     rsi, rax
.text:190A     lea     rdi, aTheInputtedFla ; "The inputted flag was RS{%s}"
.text:1911     mov     eax, 0
.text:1916     call    _printf
```

we can see that at ``` 0x18e6 ``` the program take as input ``` 0x14 ``` bytes. The bytes that we give as input represent the flag and after we have:

```assembly
.text:199A     lea     rdi, aYayYouGotTheFl ; "YAY, you got the flag!"
.text:19A1     call    _puts
.text:19A6     jmp     short loc_19B4
.text:19A8 ; ------------------------------------------------------------
.text:19A8
.text:19A8  loc_19A8:                  ; CODE XREF: main+14D↑j
.text:19A8     lea     rdi, aSorryThatSNotT ;"Sorry, that's not the flag..."
.text:19AF     call    _puts
```

In this month I have been studing angr and in this challenge, and whit angr this challenge seems very easy.

First I need to declare the input value that I give to the binary program as BVS

```python
input_len = 20

flag_chars = [claripy.BVS(f'flag_{i}',8) for i in range(input_len)]
flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')] )
```

and then I add some costraint to this BVSs for lock the possible value as printable character.

```python
for c in flag_chars:
	st.solver.add(c < 0x7f )
	st.solver.add(c > 0x20 )
```

st was declared here. sm is a Simstate.
In [angr doc site](https://docs.angr.io/core-concepts/toplevel):
> A SimState contains a program's memory, registers, filesystem data... 
> any "live data" that can be changed by execution has a home in the state. 


```python
p = angr.Project('./hard')

# here I define the flag_chars and the flag variables

st = p.factory.full_init_state(
         args=['./engine'],
         add_options=angr.options.unicorn,
         stdin=flag
     )
```
then I create a simulation sm and running it I stored all the deadend whit 'YAY' in the stdout x.posix.dumps(1) inside the ded array:

```python
sm = p.factory.simulation_manager(st)
sm.run()

ded = []
for x in sm.deadended:
	if b'YAY' in x.posix.dumps(1):
		ded.append(x)

valid = ded[0].posix.dumps(0) # dump of the stdin
#!/usr/bin/env python

import angr 
import claripy
import time


def main():

    input_len = 20

    p = angr.Project('./hard')

    flag_chars = [claripy.BVS(f'flag_{i}',8) for i in range(input_len)]
    flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')] )

    st = p.factory.full_init_state(
                args=['./engine'],
                add_options=angr.options.unicorn,
                stdin=flag
            )

    for c in flag_chars:
        st.solver.add(c < 0x7f )
        st.solver.add(c > 0x20 )

    sm = p.factory.simulation_manager(st)
    sm.run()

    ded = []
    for x in sm.deadended:
        if b'YAY' in x.posix.dumps(1):
            ded.append(x)

    valid = ded[0].posix.dumps(0)
    return valid


if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))print(valid)
```


This is the full angr script:

```python
#!/usr/bin/env python

import angr 
import claripy
import time


def main():

    input_len = 20

    p = angr.Project('./hard')

    flag_chars = [claripy.BVS(f'flag_{i}',8) for i in range(input_len)]
    flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')] )

    st = p.factory.full_init_state(
                args=['./engine'],
                add_options=angr.options.unicorn,
                stdin=flag
            )

    for c in flag_chars:
        st.solver.add(c < 0x7f )
        st.solver.add(c > 0x20 )

    sm = p.factory.simulation_manager(st)
    sm.run()

    ded = []
    for x in sm.deadended:
        if b'YAY' in x.posix.dumps(1):
            ded.append(x)

    valid_in  = ded[0].posix.dumps(0)
    valid_out = ded[0].posix.dumps(1)
    print(b'INPUT: '+valid_in)
    print(b'OUTPUT: '+valid_out)
    return


if __name__ == "__main__":
    before = time.time()
    main()
    after = time.time()
    print("Time elapsed: {}".format(after - before))
``` 

and this is the output of this script.
```bash

┌──(.angr)(eurus㉿warfare)-[~/Documents/ritsec-500]
└─$ ./solver   
WARNING | 2021-04-12 13:25:38,025 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
WARNING | 2021-04-12 13:25:38,852 | angr.simos.simos | stdin is constrained to 21 bytes (has_end=True). If you are only providing the first 21 bytes instead of the entire stdin, please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).                                                                        
WARNING | 2021-04-12 13:26:16,011 | angr.storage.memory_mixins.default_filler_mixin | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.                                                                                                                                              
WARNING | 2021-04-12 13:26:16,011 | angr.storage.memory_mixins.default_filler_mixin | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:                                                                                                                                          
WARNING | 2021-04-12 13:26:16,011 | angr.storage.memory_mixins.default_filler_mixin | 1) setting a value to the initial state
WARNING | 2021-04-12 13:26:16,011 | angr.storage.memory_mixins.default_filler_mixin | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null                                                                                                                                                    
WARNING | 2021-04-12 13:26:16,011 | angr.storage.memory_mixins.default_filler_mixin | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to suppress these messages.                                                                                                                                                        
WARNING | 2021-04-12 13:26:16,011 | angr.storage.memory_mixins.default_filler_mixin | Filling memory at 0x7fffffffffefe6e with 1 unconstrained bytes referenced from 0x40126b (PLT.perror+0x19b in hard (0x126b))                                                                                                                                 
b'INPUT: B4bys_1st_VMPr0tect?\n'
b'OUTPUT: Fill in the rest of the flag: RS{The inputted flag was RS{B4bys_1st_VMPr0tect}\n\nYAY, you got the flag!\n'
Time elapsed: 53.326435565948486

```

