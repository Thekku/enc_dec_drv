#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include<linux/slab.h>                 //kmalloc()
#include<linux/uaccess.h>              //copy_to/from_user()
#include <linux/ioctl.h>
#include <linux/scatterlist.h>
#include <linux/ratelimit.h>

#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/skcipher.h>

#define DO_ENC _IOW('a','a',unsigned char*)  //ioctl command for encryption
#define DO_DEC _IOR('a','b',unsigned char*)  //ioctl command for decryption


u8 *data = NULL;
unsigned char data1[16];
unsigned char dataOut[16] = {0};
u8 iv[16] =  {3,4,1,5,6,9,2,6,0,0,1,3,2,5,4,4};  /* dummy hardcoded IV*/
u8 key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}; /* dummy hardcoded IV*/


dev_t dev = 0;
static struct class *dev_class;
static struct cdev enc_dev;

static int __init encdec_driver_init(void);
static void __exit encdec_driver_exit(void);
static int encdec_open(struct inode *inode, struct file *file);
static int encdec_release(struct inode *inode, struct file *file);
static ssize_t encdec_read(struct file *filp, char __user *buf, size_t len,loff_t * off);
static ssize_t encdec_write(struct file *filp, const char *buf, size_t len, loff_t * off);
static long encdec_ioctl(struct file *file, unsigned int cmd, unsigned long pData);

static struct file_operations fops =
{
        .owner          = THIS_MODULE,
        .read           = encdec_read,
        .write          = encdec_write,
        .open           = encdec_open,
        .unlocked_ioctl = encdec_ioctl,
        .release        = encdec_release,
};



/******************************************** Crypto ********************************************************************/
/******************************************** Crypto ********************************************************************/
void crypto_req_done(struct crypto_async_request *req, int err)
{
	struct crypto_wait *wait = req->data;


	printk(KERN_INFO "Crypto Request Done \n");
	if (err == -EINPROGRESS)
		return;

	wait->err = err;
	complete(&wait->completion);
}



static int dec_skcipher(void)
{
        struct crypto_skcipher *tfm = NULL;
        struct skcipher_request *req = NULL;
        const size_t datasize = 16; /* data size in bytes */
        struct scatterlist sg;
        DECLARE_CRYPTO_WAIT(wait);
       
        int err,i;

        tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
        if (IS_ERR(tfm)) {
                pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
                return PTR_ERR(tfm);
        }


        err = crypto_skcipher_setkey(tfm, key, sizeof(key));
        if (err) {
                pr_err("Error setting key: %d\n", err);
                goto out;
        }

        req = skcipher_request_alloc(tfm, GFP_KERNEL);
        if (!req) {
                err = -ENOMEM;
                goto out;
        }


	for(i=0; i < datasize; i++)
		printk(KERN_INFO "%02x", data[i]);
	printk("\n Initial data");

        sg_init_one(&sg, data, datasize);
        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                           CRYPTO_TFM_REQ_MAY_SLEEP,
                                      crypto_req_done, &wait);
        skcipher_request_set_crypt(req, &sg, &sg, datasize, iv);
        err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
        if (err) {
                pr_err("Error encrypting data: %d\n", err);
                goto out;
        }

        printk(KERN_INFO "Decryption was successful\n");

	for(i=0; i < datasize; i++)
		printk(KERN_INFO "%02x", data[i]);
	printk("\n");
out:
        crypto_free_skcipher(tfm);
        skcipher_request_free(req);
        
        return err;
}



static int enc_skcipher(void)
{
        struct crypto_skcipher *tfm = NULL;
        struct skcipher_request *req = NULL;
       
        const size_t datasize = 16; /* data size in bytes */
        struct scatterlist sg;
        DECLARE_CRYPTO_WAIT(wait);
        int err,i;
	u8 *iv2;

        tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
        if (IS_ERR(tfm)) {
                pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
                return PTR_ERR(tfm);
        }

        err = crypto_skcipher_setkey(tfm, key, sizeof(key));
        if (err) {
                pr_err("Error setting key: %d\n", err);
                goto out;
        }

        /* Allocate a request object */
        req = skcipher_request_alloc(tfm, GFP_KERNEL);
        if (!req) {
                err = -ENOMEM;
                goto out;
        }

        iv2 = kmalloc(datasize, GFP_KERNEL);
        if (!iv2) {
                err = -ENOMEM;
                goto out;
        }

	memcpy(iv2,iv,datasize);

	

        
	sg_init_one(&sg, data, datasize);
        skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                           CRYPTO_TFM_REQ_MAY_SLEEP,
                                      crypto_req_done, &wait);
        skcipher_request_set_crypt(req, &sg, &sg, datasize, iv2);
        err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
        if (err) {
                pr_err("Error encrypting data: %d\n", err);
                goto out;
        }

        printk(KERN_INFO "Encryption was successful\n");

	for(i=0; i < datasize; i++)
		printk(KERN_INFO "%02x", data[i]);
	printk("\n");
out:
        crypto_free_skcipher(tfm);
        skcipher_request_free(req);
        kfree(iv2);
        return err;
}


/********************************************************************************************************************/
/***************************************** driver *******************************************************************/
/********************************************************************************************************************/
static int encdec_open(struct inode *inode, struct file *file)
{
	int err;        
	data = kmalloc(16, GFP_KERNEL);
        if (!data) {
		printk(KERN_INFO "Kernel space Memory Allocation Failed...!!!\n");
                err = -ENOMEM;
               return err;
        }
        printk(KERN_INFO "Device File Succesful!\n");
        return 0;
}


static int encdec_release(struct inode *inode, struct file *file)
{
	if(data)
		kfree(data);        
	printk(KERN_INFO "Device File Closed...!!!\n");
        return 0;
}
//Dummy
static ssize_t encdec_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
        printk(KERN_INFO "Read Function\n");
        return 0;
}
//Dummy
static ssize_t encdec_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
        printk(KERN_INFO "Write function\n");
        return 0;
}

/* IOCTL implementation */
static long encdec_ioctl(struct file *file, unsigned int cmd, unsigned long pData)
{
         
	char *inData = pData;
	switch(cmd) {
                case DO_ENC:
                        copy_from_user(data ,(unsigned char*) inData, 16);
                        printk(KERN_INFO "Data Encryption Request Received");
			printk(KERN_INFO "\n");
			enc_skcipher();
			printk(KERN_INFO "*****ENCRYPTION DONE ****\n");
			
			printk(KERN_INFO "\n");
		        copy_to_user((unsigned char*) inData, data, 16);
                        break;
                
		case DO_DEC:
                        copy_from_user(data ,(unsigned char*) inData, 16);
                        printk(KERN_INFO "Data Decryption Request Received");
			printk(KERN_INFO "\n");
			dec_skcipher();

			printk(KERN_INFO "****DECRYPTION DONE ***\n");
                        copy_to_user((unsigned char*) inData, data, 16);
                        break;
        }
        return 0;
}


static int __init encdec_driver_init(void)
{
        /*Allocating Major number*/
        if((alloc_chrdev_region(&dev, 0, 1, "EncDecDev")) <0){
                printk(KERN_INFO "Cannot allocate chardev  major no.\n");
                return -1;
        }
        printk(KERN_INFO "Major = %d Minor = %d \n",MAJOR(dev), MINOR(dev));

        /*Creating cdev structure*/
        cdev_init(&enc_dev,&fops);

        /*Adding character device to the system*/
        if((cdev_add(&enc_dev,dev,1)) < 0){
            printk(KERN_INFO "Could not add the device\n");
            goto r_class;
        }

        /*Creating struct class*/
        if((dev_class = class_create(THIS_MODULE,"EncDecDev_class")) == NULL){
            printk(KERN_INFO "Cannot create the EncDecDev_class class\n");
            goto r_class;
        }

        /*Creating device*/
        if((device_create(dev_class,NULL,dev,NULL,"encdec")) == NULL){
            printk(KERN_INFO "Cannot create the encdec Device 1\n");
            goto r_device;
        }
        printk(KERN_INFO "Device Driver Insert...Done!!!\n");
    return 0;

r_device:
        class_destroy(dev_class);
r_class:
        unregister_chrdev_region(dev,1);
        return -1;
}

void __exit encdec_driver_exit(void)
{
        device_destroy(dev_class,dev);
        class_destroy(dev_class);
        cdev_del(&enc_dev);
        unregister_chrdev_region(dev, 1);
    printk(KERN_INFO "Device Driver Remove...Done!!!\n");
}

module_init(encdec_driver_init);
module_exit(encdec_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Thekku/Github");
MODULE_DESCRIPTION("Sample Encryption/Decryption driver");
MODULE_VERSION("1.0");
MODULE_VERSION("1.0");
