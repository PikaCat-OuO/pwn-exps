#include <sys/mman.h>
#include <unistd.h>
char shellcode[] = "\x48\x31\xF6\x48\x31\xD2\x48\x31\xC0\x04\x3B\x48\xBB\x11\x2F\x62\x69\x6E\x2F\x73\x68\x48\xC1\xEB\x08\x53\x54\x5F\x0F\x05";
int main() {
  mprotect((void*)(long(shellcode) & ~0xFFF), 0x1000, PROT_READ | PROT_EXEC);
  ((void(*)())shellcode)();
  return 0;
}
