/**
 * Author: Alin Tomescu
 * Date: 11:07 PM, August 9th, 2012
 * Location: 5th Ave Laundromat, Park Slope, Brooklyn, NY (for the lulz)
 * Website: http://alinush.is-great.org
 * License: Free to use, copy and distribute
 * Warranty: None
 * Guarantees: None
 *
 * Description: This program demonstrates how to encrypt a file using AES and
 *  the OpenSSL libraries. From it, you can deduce how to use other ciphers
 *  like Blowfish or DES or how to encrypt a buffer instead of a file.
 *
 * Enjoy! :D
 */
//
//  OpenSSLAes256.m
//  FeedBack
//
//  Created by youmi on 14/11/28.
//  Copyright (c) 2014年 yuxuhong. All rights reserved.
//  对应openssl命令行的c语言代码.
//  需要引入openssl的库和头文件

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#import "OpenSSLAesCrypto.h"

#ifdef DEBUG
#define dbg(...) { fprintf(stderr, "   %s: ", __FUNCTION__); \
fprintf(stderr, __VA_ARGS__); fflush(stderr); }
#else
#define dbg(...)
#endif

#define NUM_NEEDED_ARGS (7 + 1)
//加密和解密的类型,还可以添加其它的.
#define AES_DEFAULT_MODE "aes-256-cbc"
#define EVP_CIPHERNAME_AES_CBC "aes-256-cbc"
#define EVP_CIPHERNAME_AES_CTR "aes-256-ctr"
/*
 -aes-128-cbc -aes-128-cfb -aes-128-cfb1
 -aes-128-cfb8 -aes-128-ecb -aes-128-ofb
 -aes-192-cbc -aes-192-cfb -aes-192-cfb1
 -aes-192-cfb8 -aes-192-ecb -aes-192-ofb
 -aes-256-cbc -aes-256-cfb -aes-256-cfb1
 -aes-256-cfb8 -aes-256-ecb -aes-256-ofb
 -aes128 -aes192 -aes256
 -bf -bf-cbc -bf-cfb
 -bf-ecb -bf-ofb -blowfish
 -cast -cast-cbc -cast5-cbc
 -cast5-cfb -cast5-ecb -cast5-ofb
 -des -des-cbc -des-cfb
 -des-cfb1 -des-cfb8 -des-ecb
 -des-ede -des-ede-cbc -des-ede-cfb
 -des-ede-ofb -des-ede3 -des-ede3-cbc
 -des-ede3-cfb -des-ede3-ofb -des-ofb
 -des3 -desx -desx-cbc
 -rc2 -rc2-40-cbc -rc2-64-cbc
 -rc2-cbc -rc2-cfb -rc2-ecb
 -rc2-ofb -rc4 -rc4-40
 
 附:OpenSSL加密指令语法：
 
 SYNOPSIS
 openssl enc -ciphername [-in filename] [-out filename] [-pass arg] [-e]
 [-d] [-a] [-A] [-k password] [-kfile filename] [-K key] [-iv IV] [-p]
 [-P] [-bufsize number] [-nopad] [-debug]
 说明：
 -chipername选项：加密算法，Openssl支持的算法在上面已经列出了，你只需选择其中一种算法即可实现文件加密功能。
 -in选项：输入文件，对于加密来说，输入的应该是明文文件；对于解密来说，输入的应该是加密的文件。该选项后面直接跟文件名。
 -out选项：输出文件，对于加密来说，输出的应该是加密后的文件名；对于解密来说，输出的应该是明文文件名。
 -pass选项：选择输入口令的方式，输入源可以是标准输入设备，命令行输入，文件、变量等。
 -e选项：实现加密功能（不使用-d选项的话默认是加密选项）。
 -d选项：实现解密功能。
 -a和-A选项：对文件进行BASE64编解码操作。
 -K选项：手动输入加密密钥（不使用该选项，Openssl会使用口令自动提取加密密钥）。
 -IV选项：输入初始变量（不使用该选项，Openssl会使用口令自动提取初始变量）。
 -salt选项：是否使用盐值，默认是使用的。
 -p选项：打印出加密算法使用的加密密钥。
 
用法举例：
 
 1、使用aes-128-cbc算法加密文件：
 openssl enc -aes-128-cbc -in install.log -out enc.log
 （注：这里install.log是你想要加密的文件，enc.log是加密后的文件，回车后系统会提示你输入密码。）
 2、解密刚才加密的文件：
 openssl enc -d -aes-128-cbc -in enc.log -out install.log
 （注：enc.log是刚才加密的文件，install.log是解密后的文件，-d选项实现解密功能。）
 3、加密文件后使用BASE64格式进行编码：
 openssl enc -aes-128-cbc -in install.log -out enc.log -a
 4、使用多种口令输入方式加密：
 openssl enc -des-ede3-cbc -in install.log -out enc.log -pass pass:111111
 */

#define HEX2BIN_ERR_INVALID_LENGTH -2
#define HEX2BIN_ERR_MAX_LENGTH_EXCEEDED -1
#define HEX2BIN_ERR_NON_HEX_CHAR 0
#define HEX2BIN_SUCCESS 1

#define AES_ERR_FILE_OPEN -1
#define AES_ERR_CIPHER_INIT -2
#define AES_ERR_CIPHER_UPDATE -3
#define AES_ERR_CIPHER_FINAL -4
#define AES_ERR_IO -5

#define KEY_SIZE_BYTES 32
#define IV_SIZE_BYTES 16

#define BUF_SIZE (128*1024)

typedef struct __cryptomaniac_t {
    const char * infile, * outfile;
    int encrypt;
    const EVP_CIPHER * mode;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
} cryptomaniac_t;

int aes_encrypt_file(const char * infile, const char * outfile,
                     const void * key, const void * iv, const EVP_CIPHER * cipher, int enc);

int hex2bin(const char * hex, void * bin, int max_length);

int parse_arguments(int argc, char * argv[], cryptomaniac_t * cm);
void print_usage(FILE * out, const char * name);

int aes_encrypt_file(const char * infile, const char * outfile, const void * key, const void * iv, const EVP_CIPHER * cipher, int enc)
{
    assert(cipher != NULL);
    
    int rc = -1;
    int cipher_block_size = EVP_CIPHER_block_size(cipher);
    
    assert(cipher_block_size <= BUF_SIZE);
    
    // The output buffer size needs to be bigger to accomodate incomplete blocks
    // See EVP_EncryptUpdate documentation for explanation:
    //		http://lmgtfy.com/?q=EVP_EncryptUpdate
    int insize = BUF_SIZE;
    int outsize = insize + (cipher_block_size - 1);
    
    unsigned char inbuf[insize], outbuf[outsize];
    int ofh = -1, ifh = -1;
    int u_len = 0, f_len = 0;
    
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    
    // Open the input and output files
    rc = AES_ERR_FILE_OPEN;
    if((ifh = open(infile, O_RDONLY)) == -1) {
        fprintf(stderr, "ERROR: Could not open input file %s, errno = %s\n", infile, strerror(errno));
        goto cleanup;
    }
    
    if((ofh = open(outfile, O_CREAT | O_TRUNC | O_WRONLY, 0644)) == -1) {
        fprintf(stderr, "ERROR: Could not open output file %s, errno = %s\n", outfile, strerror(errno));
        goto cleanup;
    }
    
    // Initialize the AES cipher for enc/dec
    rc = AES_ERR_CIPHER_INIT;
    if(EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, enc) == 0) {
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    // Read, pass through the cipher, write.
    int read_size, len;
    while((read_size = read(ifh, inbuf, BUF_SIZE)) > 0)
    {
        dbg("Read %d bytes, passing through CipherUpdate...\n", read_size);
        if(EVP_CipherUpdate(&ctx, outbuf, &len, inbuf, read_size) == 0) {
            rc = AES_ERR_CIPHER_UPDATE;
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            goto cleanup;
        }
        dbg("\tGot back %d bytes from CipherUpdate...\n", len);
        
        dbg("Writing %d bytes to %s...\n", len, outfile);
        if(write(ofh, outbuf, len) != len) {
            rc = AES_ERR_IO;
            fprintf(stderr, "ERROR: Writing to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto cleanup;
        }
        dbg("\tWrote %d bytes\n", len);
        
        u_len += len;
    }
    
    // Check last read succeeded
    if(read_size == -1) {
        rc = AES_ERR_IO;
        fprintf(stderr, "ERROR: Reading from the file %s failed. errno = %s\n", infile, strerror(errno));
        goto cleanup;
    }
    
    // Finalize encryption/decryption
    rc = AES_ERR_CIPHER_FINAL;
    if(EVP_CipherFinal_ex(&ctx, outbuf, &f_len) == 0) {
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    dbg("u_len = %d, f_len = %d\n", u_len, f_len);
    
    // Write the final block, if any
    if(f_len) {
        dbg("Writing final %d bytes to %s...\n", f_len, outfile);
        if(write(ofh, outbuf, f_len) != f_len) {
            rc = AES_ERR_IO;
            fprintf(stderr, "ERROR: Final write to the file %s failed. errno = %s\n", outfile, strerror(errno));
            goto cleanup;
        }
        dbg("\tWrote last %d bytes\n", f_len);
    }
    
    rc = u_len + f_len;
    
cleanup:
    EVP_CIPHER_CTX_cleanup(&ctx);
    if(ifh != -1) close(ifh);
    if(ofh != -1) close(ofh);
    
    return rc;
}

int hex2bin(const char * hex, void * bin, int max_length)
{
    int rc = 1;
    int hexlength = strlen(hex);
    
    if(hexlength % 2 == 1) {
        rc = HEX2BIN_ERR_INVALID_LENGTH;
        fprintf(stderr, "ERROR: Hex string length needs to be an even number, not %d (a byte is two hex chars)\n", hexlength);
        goto cleanup;
    }
    
    if(hexlength > max_length * 2) {
        rc = HEX2BIN_ERR_MAX_LENGTH_EXCEEDED;
        fprintf(stderr, "Hex string is too large (%d bytes) to be decoded into the specified buffer (%d bytes)\n", hexlength/2, max_length);
        goto cleanup;
    }
    
    int binlength = hexlength / 2;
    
    for (int i = 0; i < binlength; i++) {
        if (sscanf(hex, "%2hhx", (unsigned char *)(bin + i)) != 1) {
            rc = HEX2BIN_ERR_NON_HEX_CHAR;
            fprintf(stderr, "A non-hex char was found in the hex string at pos. %d or %d: [%c%c]\n",
                    i, i+1, hex[i], hex[i+1]);
            goto cleanup;
        }
        
        hex += 2;
    }
    
cleanup:
    return rc;
}

int parse_arguments(int argc, char * argv[], cryptomaniac_t * cm)
{
    int rc = -1;
    memset(cm, 0, sizeof(cryptomaniac_t));
    
    rc = 0;
    int has_iv = 0, has_key = 0;
    
    cm->infile = argv[1];
    cm->outfile = argv[2];
    cm->mode = EVP_get_cipherbyname(AES_DEFAULT_MODE);
    cm->encrypt = 1;
    
    for(int i = 3; i < argc; i++)
    {
        if(!strcmp(argv[i], "-e")) {
            cm->encrypt = 1;
        } else if(!strcmp(argv[i], "-d")) {
            cm->encrypt = 0;
        } else if(!strcmp(argv[i], "-k")) {
            if(i < argc - 1) {
                int keyLen = strlen(argv[i + 1]);
                if(keyLen % 2 == 1) {
                    fprintf(stderr, "ERROR: You need an even number of hex digits in your AES key\n");
                    goto cleanup;
                }
                
                if(keyLen != KEY_SIZE_BYTES * 2) {
                    fprintf(stderr, "ERROR: Expected %d-bit AES key. You provided a %d-bit key.\n", KEY_SIZE_BYTES * 8, keyLen / 2 * 8);
                    goto cleanup;
                }
                
                int st = hex2bin(argv[i + 1], cm->key, EVP_MAX_KEY_LENGTH);
                if(st <= 0)
                    goto cleanup;
                has_key = 1;
                i++;
            } else {
                fprintf(stderr, "ERROR: Expected hex key after -k parameter\n");
                goto cleanup;
            }
        } else if(!strcmp(argv[i], "-i")) {
            if(i < argc - 1) {
                int ivLen = strlen(argv[i + 1]);
                if(ivLen % 2 == 1) {
                    fprintf(stderr, "ERROR: You need an even number of hex digits in your AES initialization vector (IV)\n");
                    goto cleanup;
                }
                
                if(ivLen != IV_SIZE_BYTES * 2) {
                    fprintf(stderr, "ERROR: Expected %d-bit AES initialization vector (IV). You provided a %d-bit one.\n", IV_SIZE_BYTES * 8, ivLen / 2 * 8);
                    goto cleanup;
                }
                
                int st = hex2bin(argv[i + 1], cm->iv, EVP_MAX_IV_LENGTH);
                if(st <= 0)
                    goto cleanup;
                has_iv = 1;
                i++;
            } else {
                fprintf(stderr, "ERROR: Expected hex IV after -i parameter\n");
                goto cleanup;
            }
        } else if(!strcmp(argv[i], "-m")) {
            if(i < argc - 1) {
                if(!strcmp(argv[i + 1], "cbc")) {
                    cm->mode = EVP_get_cipherbyname(EVP_CIPHERNAME_AES_CBC);
                    i++;
                } else if(!strcmp(argv[i + 1], "ctr")) {
                    cm->mode = EVP_get_cipherbyname(EVP_CIPHERNAME_AES_CTR);
                    i++;
                } else {
                    fprintf(stderr, "ERROR: Expected cbc or ctr after -m, got %s\n", argv[i + 1]);
                    goto cleanup;
                }
            } else {
                fprintf(stderr, "ERROR: Expected cipher mode (cbc or ctr) after -m parameter\n");
                goto cleanup;
            }
        }
    }
    
    if(!has_iv) {
        fprintf(stderr, "ERROR: You must provide an IV value in hexadecimal using -i\n");
        goto cleanup;
    }
    
    if(!has_key) {
        fprintf(stderr, "ERROR: You must provide an encryption key in hexadecimal using -k\n");
        goto cleanup;
    }
    
    if(cm->mode == NULL) {
        fprintf(stderr, "ERROR: EVP_get_cipherbyname failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        goto cleanup;
    }
    
    rc = 1;
    
cleanup:
    return rc;
}

void print_usage(FILE * out, const char * name)
{
    fprintf(out, "Usage: %s <infile> <outfile> <options>\n", name);
    
    fprintf(out, "Cryptomaniac command-line client, version 0.1, by Alin Tomescu, http://alinush.is-great.org/\n");
    fprintf(out, "Encrypt or decrypt a file using AES256 in CBC or CTR mode. ");
    fprintf(out, "You have to provide your own key (32 bytes) and IV (16 bytes) as hexadecimal strings.\n");
    fprintf(out, "\n");
    
    fprintf(out, "  <infile> is the input file to encrypt or decrypt\n");
    fprintf(out, "  <outfile> is the output file where the encrypted or decrypted bytes will be written to\n");
    fprintf(out, "  <options> can be anyone of the following:\n");
    fprintf(out, "    -e encrypts the infile, stores the result in the outfile\n");
    fprintf(out, "    -d decrypts the infile, stores the result in the outfile\n");
    fprintf(out, "    -k <key> the encryption key to use as a hex string (32 bytes)\n");
    fprintf(out, "    -i <iv> the IV to use as a hex string (16 bytes)\n");
    fprintf(out, "    -m <mode> the cipher block-mode to use (this can be cbc or ctr)\n");
    fprintf(out, "\n");
    
    fprintf(out, "Examples:\n");
    fprintf(out, "=========\n");
    fprintf(out, "\n");
    
    fprintf(out, "  Encrypting a file:\n");
    fprintf(out, "  ------------------\n");
    fprintf(out, "  %s secrets.txt secrets.safe -e -k ae48fbc31957 -iv 39eab239867dfe\n", name);
    fprintf(out, "\n");
    
    fprintf(out, "  Decrypting a file:\n");
    fprintf(out, "  ------------------\n");
    fprintf(out, "  %s secretes.safe secrets.revealed -d -k ae48fbc31957 -iv 39eab239867dfe\n", name);
    fprintf(out, "\n");
}

int OpenSSLAesCrypto(int argc, char * argv[])
{
    if(argc < NUM_NEEDED_ARGS) {
        print_usage(stderr, argv[0]);
        return 1;
    }
    
    // Initializing the AES cipher in parse_arguments requires this call
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Parse arguments
    cryptomaniac_t cm;
    if(parse_arguments(argc, argv, &cm) <= 0)
        return 1;
    
    // Encrypt/decrypt file
    int st;
    if((st = aes_encrypt_file(cm.infile, cm.outfile, cm.key, cm.iv, cm.mode, cm.encrypt)) <= 0)
    {
        fprintf(stderr, "ERROR: %s failed\n", cm.encrypt ? "Encryption" : "Decryption");
        return 1;
    }
    
    dbg("Exited gracefully!\n");
    return 0;
}

int OpenSSL_AES256CBC_Encrypt_File(NSString *inFile, NSString *outFile, NSString *key, NSString *iv)
{
    // 加密文件
    // 对应openssl的命令行如下
    // openssl enc -e -aes-256-cbc -p -in a.txt -out a.tt -K ae48fbc319570000000000000000000000000000000000000000000000000000 -iv 39eab239867dfe000000000000000000 -nosalt
    int argc = 10;
    char *argv[12]={"./cryptomaniac", [inFile UTF8String], [outFile UTF8String], "-e", "-k", [key UTF8String], "-i", [iv UTF8String], "-m", "cbc"};
    
    return OpenSSLAesCrypto(argc, argv);
}
int OpenSSL_AES256CBC_Decrypt_File(NSString *inFile, NSString *outFile, NSString *key, NSString *iv)
{
    // 解密文件
    // 对应openssl的命令行如下
    // openssl enc -d -aes-256-cbc -p -in a.tt -out a.txt -K ae48fbc319570000000000000000000000000000000000000000000000000000 -iv 39eab239867dfe000000000000000000 -nosalt
    int argc = 10;
    char *argv[12]={"./cryptomaniac", [inFile UTF8String], [outFile UTF8String], "-d", "-k", [key UTF8String], "-i", [iv UTF8String], "-m", "cbc"};
    
    return OpenSSLAesCrypto(argc, argv);
}



