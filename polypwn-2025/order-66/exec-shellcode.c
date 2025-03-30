#include <unistd.h>

int main() {
    char shellcode[200];

    read(0, shellcode, 200);
    ((void (*) (void)) shellcode) ();

    return 0;
}
