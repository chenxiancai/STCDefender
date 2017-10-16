//
//  STCDF.m
//  STCDF
//
//  Created by chenxiancai on 31/08/2017.
//  Copyright © 2017 stevchen. All rights reserved.
//

#import "STCDF.h"

// For debugger_sysctl
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <mach/machine.h>

// For ioctl
#include <termios.h>
#include <sys/ioctl.h>

// For task_get_exception_ports
#include <mach/task.h>
#include <mach/mach_init.h>

// For cryptid
#import <dlfcn.h>
#import <mach-o/loader.h>
#import <CommonCrypto/CommonDigest.h>
#import <mach-o/fat.h>

// For jailbreak
#import <sys/stat.h>

#ifndef __OPTIMIZE__
    #define NSLog(...)\
NSLog(__VA_ARGS__)
    #else
#define NSLog(...)\
    {}
#endif

#define STRING_XOR(_output, _input, _length)                                    \
\
for (int16_t _i = 0; _i < _length; _i++) \
{ _output[_i] = (char)_input[_i] ^ (_i + 1024 * (_i + 1) / 2) ^ (0x66aa >> (_i + 1) % 4);}\

#define sta_md5(_input, _output)\
    unsigned char temp[CC_MD5_DIGEST_LENGTH];\
    CC_LONG len = (CC_LONG)strlen(_input);\
    CC_MD5(_input, len, temp);\
    for (int i = 0 ; i <CC_MD5_DIGEST_LENGTH; i++ ) {\
        [_output appendFormat:@"%02X", temp[i]];\
    }

//NSString * str_cf(const char * _input)
//{
//    int len = (int)[[NSString stringWithUTF8String:_input] length];
//    char *_temp = (char *)malloc((len + 1) * sizeof(char));
//    int16_t *_output = (int16_t *)malloc((len + 2) * sizeof(int16_t));
//    
//    NSMutableString *str = [NSMutableString string];
//    for (int16_t i = 0; i < len; i++) {
//        _temp[i] = _input[i];
//    }
//    _temp[len] = 0x0;
//    STRING_XOR(_output, _temp, len + 1);
//    _output[len + 1] = 0x0;
//    for (int16_t i = 0; i < len + 2; i++) {
//        [str appendString:[NSString stringWithFormat:@"0x%0x,",_output[i]]];
//    }
//    free(_output);
//    free(_temp);
//    return [NSString stringWithString:str];
//}

static long alt = 0;

typedef void (^cbBlock) (void);

static __attribute__((always_inline)) void exitApp()
{
    NSMutableArray *array = [[NSMutableArray alloc] init];
    [array addObject:[[NSString alloc] initWithString:NSStringFromClass([NSObject class])]];
    while (1) {
        [array addObject:[array mutableCopy]];
    }
}
#pragma mark - 反动态调试

// This function uses sysctl to check for attached debuggers.
// https://developer.apple.com/library/mac/qa/qa1361/_index.html
// http://www.coredump.gr/articles/ios-anti-debugging-protections-part-2/

// Returns true if the current process is being debugged (either
// running under the debugger or has a debugger attached post facto).
static __attribute__((always_inline)) bool db_sc(void)
{
    int mib[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);

    // Initialize the flags so that, if sysctl fails for some bizarre
    // reason, we get a predictable result.

    info.kp_proc.p_flag = 0;

    // Initialize mib, which tells sysctl the info we want, in this case
    // we're looking for information about a specific process ID.

    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    // Call sysctl.
    if (sysctl(mib, 4, &info, &info_size, NULL, 0) == -1){
        perror("perror sysctl");
    }

    // We're being debugged if the P_TRACED flag is set.

    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

static __attribute__((always_inline)) void asmInvertDebug()
{
#if defined(__arm64__)
        __asm__("mov X0, #31 \t\n"
                "mov X1, #0 \t\n"
                "mov X2, #0 \t\n"
                "mov X3, #0 \t\n"
                "mov w16, #26 \t\n"
                "svc #0x80"
                );
#elif defined(__arm__)
        __asm__(
                "mov r0, #31 \t\n"
                "mov r1, #0 \t\n"
                "mov r2, #0 \t\n"
                "mov r3, #0 \t\n"
                "mov ip, #26 \t\n"
                "svc #0x80"
                );
#endif
}

static __attribute__((always_inline)) void ptraceInvertDebug()
{
    // If enabled the program should exit with code 0377 in GDB
    // Program exited with code 0377.
    if (db_sc()){
        NSLog(@"db_sc");
        exitApp();
    }

    // Another way of figuring out if LLDB is attached.
    if (isatty(1)) {
        NSLog(@"isatty");
        exitApp();
    }

    // Yet another way of figuring out if LLDB is attached.
    if (!ioctl(1, TIOCGWINSZ)) {
        NSLog(@"!ioctl(1, TIOCGWINSZ)");
        exitApp();
    }
}

#pragma mark - 越狱检测

#define FILENAME_PRIMER 230

#define FILENAME_XOR(_key, _input, _length)                                    \
\
for (size_t _i = 0; _i < _length; _i++) { _input[_i] ^= _key; }            \

/*
 ------------------------------------------------
 chkFiles
 ------------------------------------------------
 /Applications/Cydia.app
 /Library/MobileSubstrate/MobileSubstrate.dylib
 /var/cache/apt
 /var/lib/apt
 /var/lib/cydia
 /var/log/syslog
 /var/tmp/cydia.log
 /bin/bash
 /bin/sh
 /usr/sbin/sshd
 /usr/libexec/ssh-keysign
 /etc/ssh/sshd_config
 /etc/apt
 
 */

#define checkFiles(fcb) {                                                      \
    \
    char chkFiles[] = {                                                        \
    \
     201,167,150,150,138,143,133,135,146,143,137,136,149,201,165,159,130,143   \
    ,135,200,135,150,150,0                                                     \
    ,200,171,142,133,149,134,149,158,200,170,136,133,142,139,130,180,146,133   \
    ,148,147,149,134,147,130,200,170,136,133,142,139,130,180,146,133,148,147   \
    ,149,134,147,130,201,131,158,139,142,133,0                                 \
    ,199,158,137,154,199,139,137,139,128,141,199,137,152,156,0                 \
    ,198,159,136,155,198,133,128,139,198,136,153,157,0                         \
    ,197,156,139,152,197,134,131,136,197,137,147,142,131,139,0                 \
    ,196,157,138,153,196,135,132,140,196,152,146,152,135,132,140,0             \
    ,195,154,141,158,195,152,129,156,195,143,149,136,133,141,194,128,131,139,0 \
    ,194,143,132,131,194,143,140,158,133,0                                     \
    ,193,140,135,128,193,157,134,0                                             \
    ,192,154,156,157,192,156,141,134,129,192,156,156,135,139,0                 \
    ,223,133,131,130,223,156,153,146,149,136,149,147,223,131,131,152,221,155   \
    ,149,137,131,153,151,158,0                                                 \
    ,222,148,133,146,222,130,130,153,222,130,130,153,149,174,146,158,159,151   \
    ,152,150,0                                                                 \
    ,221,151,134,145,221,147,130,134,0                                         \
    ,0                                                                         \
    };                                                                         \
    \
    struct stat fStat;                                                         \
    \
    char    *fp = chkFiles;                                                    \
    size_t flen = strlen(fp);                                                  \
    int    fxor = FILENAME_PRIMER;                                             \
    int    fcnt = 0;                                                           \
    \
    while (flen) {                                                             \
    \
        fxor    = FILENAME_PRIMER + fcnt;                                      \
    \
        FILENAME_XOR(fxor, fp, flen);                                          \
    \
        if (stat(fp, &fStat) == 0) { fcb(); }                                  \
    \
        fp     += flen + 1;                                                    \
        flen    = strlen(fp);                                                  \
    \
        fcnt++;                                                                \
    }                                                                          \
}

/*
 ------------------------------------------------
 chkLinks
 ------------------------------------------------
 /Library/Ringtones
 /Library/Wallpaper
 /usr/arm-apple-darwin9
 /usr/include
 /usr/libexec
 /usr/share
 /Applications
 
 */

#define checkLinks(lcb) {                                                      \
    \
    char chkLinks[] = {                                                        \
        \
         201,170,143,132,148,135,148,159,201,180,143,136,129,146,137,136,131   \
        ,149,0                                                                 \
        ,200,171,142,133,149,134,149,158,200,176,134,139,139,151,134,151,130   \
        ,149,0                                                                 \
        ,199,157,155,154,199,137,154,133,197,137,152,152,132,141,197,140,137   \
        ,154,159,129,134,209,0                                                 \
        ,198,156,154,155,198,128,135,138,133,156,141,140,0                     \
        ,197,159,153,152,197,134,131,136,143,146,143,137,0                     \
        ,196,158,152,153,196,152,131,138,153,142,0                             \
        ,195,173,156,156,128,133,143,141,152,133,131,130,159,0                 \
        ,0                                                                     \
        \
    };                                                                         \
    \
    struct stat lStat;                                                         \
    \
    char    *lp = chkLinks;                                                    \
    size_t llen = strlen(lp);                                                  \
    int    lxor = FILENAME_PRIMER;                                             \
    int    lcnt = 0;                                                           \
    \
    while (llen) {                                                             \
    \
        lxor    = FILENAME_PRIMER + lcnt;                                      \
    \
        FILENAME_XOR(lxor, lp, llen);                                          \
    \
        if ( lstat(lp, &lStat) == 0)                                           \
    \
            if (lStat.st_mode & S_IFLNK) { lcb(); }                            \
    \
    \
        lp     += llen + 1;                                                    \
        llen    = strlen(lp);                                                  \
    \
        lcnt++;                                                                \
    }                                                                          \
}

#define checkFork(forkCb) {                                                    \
    \
    pid_t child = fork();                                                      \
    \
    if (child == 0) { exit(0); }                                               \
    if (child > 0)  { forkCb();}                                               \
}

#pragma mark - 反二进制文件破解

//otool -l STCDF | grep LC_ENCRYPTION_INFO -A5
/*
cmd LC_ENCRYPTION_INFO
cmdsize 20
cryptoff 16384
cryptsize 16384
cryptid 0
Load command 13
--
cmd LC_ENCRYPTION_INFO_64
cmdsize 24
cryptoff 16384
cryptsize 16384
cryptid 0
pad 0
*/
static __attribute__((always_inline)) int enc(int argc, char *argv[]) {
    
    const void *binaryBase;
    struct load_command *machoCmd = NULL;
    const struct mach_header *machoHeader;
    
    NSString *path = [[NSBundle mainBundle] executablePath];
    NSData *filedata = [NSData dataWithContentsOfFile:path];
    binaryBase = (char *)[filedata bytes];
    machoHeader = (const struct mach_header *) binaryBase;
    
    if(machoHeader->magic == FAT_CIGAM){
        unsigned int offset = 0;
        struct fat_arch *fatArch = (struct fat_arch *)((struct fat_header *)machoHeader + 1);
        struct fat_header *fatHeader = (struct fat_header *)machoHeader;
        for(uint32_t i = 0; i < ntohl(fatHeader->nfat_arch); i++){
            // check 32bit section for 32bit architecture
            if(sizeof(int *) == 4 && !(ntohl(fatArch->cputype) & CPU_ARCH_ABI64)){
                offset = ntohl(fatArch->offset);
                break;
            // and 64bit section for 64bit architecture
            }else if(sizeof(int *) == 8 && (ntohl(fatArch->cputype) & CPU_ARCH_ABI64)){
                offset = ntohl(fatArch->offset);
                break;
            }
            fatArch = (struct fat_arch *)((uint8_t *)fatArch + sizeof(struct fat_arch));
        }
        machoHeader = (const struct mach_header *)((uint8_t *)machoHeader + offset);
    }
    // 32bit
    if(machoHeader->magic == MH_MAGIC){
        machoCmd = (struct load_command *)((struct mach_header *)machoHeader + 1);
    // 64bit
    }else if(machoHeader->magic == MH_MAGIC_64){
        machoCmd = (struct load_command *)((struct mach_header_64 *)machoHeader + 1);
    }
    
    for(uint32_t i=0; i < machoHeader->ncmds && machoCmd != NULL; i++){
        if(machoCmd->cmd == LC_ENCRYPTION_INFO){
            struct encryption_info_command *cryptCmd = (struct encryption_info_command *) machoCmd;
            return cryptCmd->cryptid;
        }
        if(machoCmd->cmd == LC_ENCRYPTION_INFO_64){
            struct encryption_info_command_64 *cryptCmd = (struct encryption_info_command_64 *) machoCmd;
            return cryptCmd->cryptid;
        }
        machoCmd = (struct load_command *)((uint8_t *)machoCmd + machoCmd->cmdsize);
    }
    return 0; // couldn't find cryptcmd
}

#pragma mark - 反重签名
// security cms -D -i embedded.mobileprovision
static __attribute__((always_inline)) NSDictionary *gmp()
{
    static NSDictionary* mp = nil;
    if (!mp) {
        
        NSString *path = nil;
        {
            //mobileprovision
            int16_t tn[] = {0x3138,0x1dc4,0xab5,0x6ec0,0x393d,
                            0x15ca,0x2a3,0x76df,0x2132,0xdd5,
                            0x1ab6,0x7ed2,0x2930,0x5c8,0x12b5,
                            0x46a5,0x0};
            char rtn[17];
            STRING_XOR(rtn, tn, sizeof(tn)/sizeof(int16_t));
            
            //embedded
            int16_t n[] = {0x3130,0x1dc6,0xab5,0x6ecc,0x3935,
                           0x15cb,0x2b6,0x76c9,0x215d,0x0};
            char rn[10];
            STRING_XOR(rn, n, sizeof(n)/sizeof(int16_t));
            
            path = [[NSBundle mainBundle] pathForResource:[NSString stringWithCString:rn encoding:NSASCIIStringEncoding] ofType:[NSString stringWithCString:rtn encoding:NSASCIIStringEncoding]];
        }
        if (!path) {
            mp = @{};
            return mp;
        }
        // NSISOLatin1 keeps the binary wrapper from being parsed as unicode and dropped as invalid
        NSString *bString = [NSString stringWithContentsOfFile:path encoding:NSISOLatin1StringEncoding error:NULL];
        if (!bString) {
            return nil;
        }
        BOOL ok;
        NSScanner *scanner = [NSScanner scannerWithString:bString];
        {
            // <plist
            int16_t n[] = {0x3169,0x1ddb,0xabb,0x6ec0,0x3922,
                           0x15db,0x2d3,0x0};
            char rn[8];
            STRING_XOR(rn, n, sizeof(n)/sizeof(int16_t));
            ok = [scanner scanUpToString:[NSString stringWithCString:rn encoding:NSASCIIStringEncoding] intoString:nil];
        }
        if (!ok) {
            return nil;
        }
        NSString *pString;
        {
            // </plist>
            int16_t n[] = {0x3169,0x1d84,0xaa7,0x6ec5,0x3938,
                           0x15dc,0x2a7,0x7693,0x215d,0x0};
            char rn[10];
            STRING_XOR(rn, n, sizeof(n)/sizeof(int16_t));
            ok = [scanner scanUpToString:[NSString stringWithCString:rn encoding:NSASCIIStringEncoding] intoString:&pString];
        }
        if (!ok) {
            return nil;
        }
        {
            // </plist>
            int16_t n[] = {0x3169,0x1d84,0xaa7,0x6ec5,0x3938,
                           0x15dc,0x2a7,0x7693,0x215d,0x0};
            char rn[10];
            STRING_XOR(rn, n, sizeof(n)/sizeof(int16_t));
            pString = [NSString stringWithFormat:@"%@%@",pString,[NSString stringWithCString:rn encoding:NSASCIIStringEncoding]];
        }
        // juggle latin1 back to utf-8!
        NSData *plistdata_latin1 = [pString dataUsingEncoding:NSISOLatin1StringEncoding];
        NSError *error = nil;
        mp = [[NSPropertyListSerialization propertyListWithData:plistdata_latin1 options:NSPropertyListImmutable format:NULL error:&error] copy];
        if (error) {
            return nil;
        }
    }
    return mp;
}

static __attribute__((always_inline)) bool mp(const char *aidh, const char *bidh)
{
    if (aidh == NULL || bidh == NULL) {
        assert(aidh != NULL);
        assert(bidh != NULL);
        return -1;
    }
    const char *caid = NULL;
    NSDictionary *mpd = gmp();
    if ([[mpd allKeys] count] > 0) {
        // Entitlements
        int16_t n1[] = {0x3110,0x1dc5,0xaa3,0x6ec0,0x3925,
                       0x15c3,0x2b6,0x76c0,0x2138,0xdcd,
                       0x1aab,0x7ed2,0x2959,0x0};
        char rn1[14];
        STRING_XOR(rn1, n1, sizeof(n1)/sizeof(int16_t));
        // application-identifier
        int16_t n2[] = {0x3134,0x1ddb,0xaa7,0x6ec5,0x3938,
                        0x15cc,0x2b2,0x76d9,0x2134,0xdcc,
                        0x1ab1,0x7e8c,0x2930,0x5c3,0x12be,
                        0x46cb,0x1131,0x3dd2,0x2aa1,0x4ed0,
                        0x1924,0x35cd,0x22c3,0x0};
        char rn2[14];
        STRING_XOR(rn2, n2, sizeof(n2)/sizeof(int16_t));
        
        caid = [[[mpd objectForKey:[NSString stringWithCString:rn1 encoding:NSASCIIStringEncoding]] objectForKey:[NSString stringWithCString:rn2 encoding:NSASCIIStringEncoding]] UTF8String];
    }
    const char *cbid = [[[NSBundle mainBundle] bundleIdentifier] UTF8String];
    
    // check bundleId
    if (cbid != NULL) {
        unsigned char cbidh[CC_MD5_DIGEST_LENGTH];

        CC_LONG cbidlen = (CC_LONG)strlen(cbid);
        CC_MD5(cbid, cbidlen, cbidh);
        
        NSMutableString *str = [NSMutableString string];
        for (int i = 0 ; i <CC_MD5_DIGEST_LENGTH; i++ ) {
            [str appendFormat:@"%02X", cbidh[i]];
        }
        
        if (strcmp((const char *)[str UTF8String], bidh) != 0) {
            return NO;
        }
    }
    
    // check application-identifier
    if (caid != NULL) {
        unsigned char caidh[CC_MD5_DIGEST_LENGTH];
        
        CC_LONG caidlen = (CC_LONG)strlen(caid);
        CC_MD5(caid, caidlen, caidh);
        
        NSMutableString *str1 = [NSMutableString string];
        for (int i = 0 ; i <CC_MD5_DIGEST_LENGTH; i++ ) {
            [str1 appendFormat:@"%02X", caidh[i]];
        }
        
        if (strcmp((const char *)[str1 UTF8String], aidh) != 0) {
            return NO;
        }
    }
    return YES;
}

__attribute__((always_inline)) const char *calcString_md5(const char * str)
{
    NSMutableString *md5 = [NSMutableString string];
    sta_md5(str, md5);
    return  [md5 UTF8String];
}

#pragma mark - 文件篡改校验

__attribute__((always_inline)) NSArray *searchSourceFilesInPath(NSString *path)
{
    NSMutableArray *files = [NSMutableArray array];
    NSFileManager * fileManger = [NSFileManager defaultManager];
    BOOL isDir = NO;
    BOOL isExist = [fileManger fileExistsAtPath:path isDirectory:&isDir];
    if (isExist) {
        if (isDir) {
            NSArray * dirArray = [fileManger contentsOfDirectoryAtPath:path error:nil];
            NSString * subPath = nil;
            for (NSString * str in dirArray) {
                subPath  = [path stringByAppendingPathComponent:str];
                BOOL issubDir = NO;
                [fileManger fileExistsAtPath:subPath isDirectory:&issubDir];
                NSArray *fileArray = searchSourceFilesInPath(subPath);
                [files addObjectsFromArray:fileArray];
            }
        }else{
            return @[path];
        }
    }else{
        return files;
    }
    return files;
}

__attribute__((always_inline)) const char *calcFile_md5()
{
    NSString *path = [[NSBundle mainBundle] bundlePath];
    NSArray *files = searchSourceFilesInPath(path);
    NSMutableData *fileData = [NSMutableData data];
    for (NSString *filePath in files) {
        // you can add other type of resources
        if ([filePath hasSuffix:@"png"] ||
            [filePath hasSuffix:@"jpg"] ) {
            NSData *data = [NSData dataWithContentsOfFile:filePath];
            [fileData appendData:data];
        }
    }
    NSString *str = [fileData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSMutableString *md5 = [NSMutableString string];
    const char *string = [str UTF8String];
    sta_md5(string, md5);
    return [md5 UTF8String];
}

__attribute__((always_inline)) void file_check(struct struct_sta *sta)
{
    if (sta == NULL || sta->sta(-1,NULL,sta) >= 0) {
        NSLog(@"sta == NULL || sta->sta(-1,NULL,sta) >= 0");
        exitApp();
    }
    
    const char *md5 = calcFile_md5();
    static BOOL isCheck = NO;
    if (![[NSString stringWithUTF8String:md5] isEqualToString:[NSString stringWithUTF8String:sta->fileh]]) {
        if (!isCheck) {
            isCheck = YES;
            sta->alert(alert_fileCheck);
            alt |= alert_fileCheck;
        }
    }
}

#pragma mark - 安全检测

__attribute__((always_inline)) void debug_check(struct struct_sta *sta)
{
    ptraceInvertDebug();
    asmInvertDebug();
    if (alt > alert_jailBreak){
        NSLog(@"alt > alert_jailBreak");
        exitApp();
    } else {
        if (!enc(0, NULL)) {
            NSLog(@"!enc(0, NULL)");
            exitApp();
        }
        if (!mp(sta->aidh, sta->bidh)) {
            NSLog(@"!mp(sta->aidh, sta->bidh");
            exitApp();
        }
    }
    if (sta == NULL || sta->sta(-1,NULL,sta) >= 0) {
        NSLog(@"sta == NULL || sta->sta(-1,NULL,sta) >= 0");
        exitApp();
    }
}

int sta(int argc, char * argv[], struct struct_sta *sta) {
    
    NSLog(@"struct_sta");

    // check debug
    ptraceInvertDebug();
    asmInvertDebug();

    // check jailbreak
    static BOOL isJailBreak = NO;
    cbBlock chkCallback  = ^{
        if (argc >= 0 && !isJailBreak) {
            isJailBreak = YES;
            sta->alert(alert_jailBreak);
            alt |= alert_jailBreak;
        }
    };
    
    checkFork(chkCallback);
    checkFiles(chkCallback);
    checkLinks(chkCallback);
    
    if (sta->main != NULL) {
        sta->main = enc;
    } else {
        return -1;
    }
    
    // check cryptid
    static BOOL isDec = NO;
    if (!sta->main(0, NULL)) {
        if (argc >= 0 && !isDec) {
            isDec = YES;
            sta->alert(alert_decrypt);
            alt |= alert_decrypt;
        }
    }

    // check resign
    static BOOL isRes = NO;
    if (!mp(sta->aidh, sta->bidh)) {
        if (argc >= 0 && !isRes) {
            isRes = YES;
            sta->alert(alert_reSign);
            alt |= alert_reSign;
        }
    }

    if (argc < 0) {
        return -1;
    }
    // enter app
    if (sta->entry != NULL && sta->name != NULL) {
        return sta->entry(argc, argv, nil, [NSString stringWithUTF8String:sta->name]);
     } else {
        return -1;
    }
}

