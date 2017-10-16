//
//  STCDF.h
//  STCDF
//
//  Created by chenxiancai on 31/08/2017.
//  Copyright © 2017 stevchen. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum : NSUInteger {
    alert_jailBreak = 1L,
    alert_reSign = 1L<<1,
    alert_decrypt = 1L<<2,
    alert_fileCheck = 1L<<3,
} AlertType;

// Security to Attack struct
struct struct_sta {
    //file md5,can not be NULL
    const char *fileh;
    //application-identifier md5, can not be NULL
    const char *aidh;
    //BundleId md5 , can not be NULL
    const char *bidh;
    //delegateClassName, can be NULL
    const char *name;
    //appEntry, can not be NULL
    int (*entry)(int argc, char *argv[], NSString *principalClassName, NSString * delegateClassName);
    //defenderEntry, can not be NULL
    int (*sta)(int argc, char * argv[], struct struct_sta *sta);
    //main shadow function, can not be NULL
    int (*main)(int argc, char *argv[]);
    //alert, can be NULL
    void (*alert)(AlertType type);
};

/**
 Defender entry

 @param argc arg count
 @param argv arg list
 @param sta defender struct
 @return entry result
 */
int sta(int argc, char * argv[], struct struct_sta *sta);

// debug check
void debug_check(struct struct_sta *sta);

// file check
void file_check(struct struct_sta *sta);

// calc file md5
const char *calcFile_md5();

// calc string md5
const char *calcString_md5(const char * str);


