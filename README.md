# Sample Kernel driver for Dncryption/Decryption
This git contains source code for 
## 1. Kernel driver for doing Encryption/Decryption in the kernel space using Scatterlist. Driver is built as module. Path is /drv

  build steps:
 
      cd drv
      apt-get install kernel-headers-$(uname -r)
      make all

  EncDec.ko will be generated after above steps

## 2. An userspace sample application to connect with Kernel driver 

  build steps:
     cd app
     gcc -o testapp userapp.c

  tesapp will be generated after above steps


## How test
### 1. Insert the module
__                                                                                                                                                                                                                                             
┌──(kali㉿secbox)-[~/test/EncDec]
└─$ sudo insmod drv/EncDec.ko 
[sudo] password for kali: 

### 2. Verify Module inserted properly                                                                                                                                                                                                           
┌──(kali㉿secbox)-[~/test/EncDec]
└─$ lsmod | grep EncDec
EncDec                 16384  0
                                                                                                                                                                                                                                             
┌──(kali㉿secbox)-[~/test/EncDec]
└─$ ls -l /dev/encdec  
crw------- 1 root root 245, 0 Dec 15 08:40 /dev/encdec
                                                                                                                                                                                                                                             
┌──(kali㉿secbox)-[~/test/EncDec]
└─$ 
__
### 3. Run the testapp

   sudo app/testapp         

  __ Opening Driver
  input data is 0123456789abcdef
  Sending the data for encryption
  Encrypted data is 0e4bc646c82e6a4257bf3c227e5f5bb
  Sending the data for deryption
  Decrypted data is 0123456789abcdef
  Closing Driver __
                                                                                                                                                                                                                                             
┌──(kali㉿secbox)-[~/test/EncDec]
└─$ 



