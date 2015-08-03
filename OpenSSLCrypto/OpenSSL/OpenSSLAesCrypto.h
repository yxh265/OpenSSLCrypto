//
//  OpenSSLAes256.h
//  FeedBack
//
//  Created by youmi on 14/11/28.
//  Copyright (c) 2014年 yuxuhong. All rights reserved.
//
#import <UIKit/UIKit.h>

int OpenSSL_AES256CBC_Encrypt_File(NSString *inFile, NSString *outFile, NSString *key, NSString *iv);

int OpenSSL_AES256CBC_Decrypt_File(NSString *inFile, NSString *outFile, NSString *key, NSString *iv);