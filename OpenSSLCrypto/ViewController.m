//
//  ViewController.m
//  OpenSSLCrypto
//
//  Created by tamik on 15/8/3.
//  Copyright (c) 2015年 yuxuhong. All rights reserved.
//

#import "ViewController.h"
#import "OpenSSLAesCrypto.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    
    NSString *source = [[NSBundle mainBundle] pathForResource:@"testfile.txt" ofType:nil];//加密的文件首先是加到bundle里的.
    
    NSFileManager *manager = [NSFileManager defaultManager];
    NSString *path = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) objectAtIndex:0];
    NSString *normalFile = [path stringByAppendingPathComponent:@"testfile.txt"];
    NSString *encodeFile = [path stringByAppendingPathComponent:@"testfile.tt"];//加密的文件
    NSString *dncodeFile = [path stringByAppendingPathComponent:@"testfile2.txt"];//解密的文件
    
    
    //从bundle里复制文件到docment里运行。
    [manager copyItemAtPath:source toPath:normalFile error:nil];
    
    
    NSString *key = @"ae48fbc319570000000000000000000000000000000000000000000000000000";
    NSString *iv = @"39eab239867dfe000000000000000000";
    
    //对文件进行加密，同命令行里运行了这个一样
    // openssl enc -e -aes-256-cbc -p -in testfile.txt -out testfile.tt -K ae48fbc319570000000000000000000000000000000000000000000000000000 -iv 39eab239867dfe000000000000000000 -nosalt
    OpenSSL_AES256CBC_Encrypt_File(normalFile, encodeFile, key, iv);
    
    
    
    //对文件进行解密，同命令行里运行了这个一样
    // openssl enc -d -aes-256-cbc -p -in testfile.tt -out testfile2.txt -K ae48fbc319570000000000000000000000000000000000000000000000000000 -iv 39eab239867dfe000000000000000000 -nosalt
    OpenSSL_AES256CBC_Decrypt_File(encodeFile, dncodeFile, key, iv);
    
    NSLog(@"===========================\n===========================\n===========================\n");
    NSLog(@"====原文件：%@",normalFile);
    NSLog(@"====加密后的文件：%@",encodeFile);
    NSLog(@"====解密后的文件：%@",dncodeFile);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
