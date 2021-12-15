#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include<sys/ioctl.h>

#define DO_ENC _IOW('a','a',unsigned char*)  //ioctl command for encryption
#define DO_DEC _IOR('a','b',unsigned char*)  //ioctl command for decryption

int main()
{
    int fd;
    int32_t value, i;
	volatile unsigned char test_data[16] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    printf("*********************************v2\n");
    

	printf("\nOpening Driver\n");
	fd = open("/dev/encdec", O_RDWR);
	if(fd < 0) {
			printf("Cannot open device file...\n");
			return 0;
	}



	printf("input data is ");
	for(i=0; i < 16; i++)
		printf("%x", test_data[i]);
	printf("\n");


	/*********************** Encryption ***********************************/
    printf("Sending the data for encryption\n");
	ioctl(fd, DO_ENC, test_data); 
    printf("Encrypted data is ");

	for(i=0; i < 16; i++)
		printf("%x", test_data[i]);
	printf("\n");


	/*********************** Decrypton ***********************************/
	printf("Sending the data for deryption\n");
	ioctl(fd, DO_DEC, test_data);

  	printf("Decrypted data is ");
	for(i=0; i < 16; i++)
		printf("%x", test_data[i]);
	printf("\n");


	printf("Closing Driver\n");
	close(fd);
}
