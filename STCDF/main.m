//
//  main.m
//  STCDF
//
//  Created by chenxiancai on 31/08/2017.
//  Copyright © 2017 stevchen. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import "main.h"

struct struct_sta sta_obj;

void alert(AlertType type)
{
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if ((type & alert_jailBreak) == alert_jailBreak) {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"越狱提示" message:@"您的设备已越狱，存在安全隐患，请谨慎使用！" delegate:[UIApplication sharedApplication].delegate cancelButtonTitle:@"确定" otherButtonTitles: nil];
            [alert show];
        } else if ((type & alert_reSign) == alert_reSign) {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"签名错误提示" message:@"应用签名错误，请在正规渠道重新下载安装APP" delegate:[UIApplication sharedApplication].delegate cancelButtonTitle:@"确定" otherButtonTitles: nil];
            [alert show];
        } else if ((type & alert_decrypt) == alert_decrypt) {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"应用破解提示" message:@"应用已被破解，请在正规渠道重新下载安装APP" delegate:[UIApplication sharedApplication].delegate cancelButtonTitle:@"确定" otherButtonTitles: nil];
            [alert show];
        } else if ((type & alert_fileCheck) == alert_fileCheck) {
            UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"文件篡改提示" message:@"应用已被篡改，请在正规渠道重新下载安装APP" delegate:[UIApplication sharedApplication].delegate cancelButtonTitle:@"确定" otherButtonTitles: nil];
            [alert show];
        }
    });
}

int main(int argc, char * argv[]) {
    @autoreleasepool {
#if !DEBUG
        sta_obj.fileh = [@"C7BB8ACA97F45BB6E0C062654E5BA0CE" UTF8String];
        sta_obj.aidh = [@"FC4593E5DAA305F9B51AA9752DB69AD1" UTF8String];
        sta_obj.bidh = [@"7ADC6D976C1D32E4C65520DF9766BDBC" UTF8String];
        sta_obj.name = [NSStringFromClass([AppDelegate class]) UTF8String];
        sta_obj.sta = sta;
        sta_obj.entry = UIApplicationMain;
        sta_obj.main = main;
        sta_obj.alert = alert;
        return sta_obj.sta(argc,argv,&sta_obj);
#else
        // 1.计算文件md5
        NSLog(@"file md5 is :%s",calcFile_md5());
        // 2.计算application-identifier
        NSLog(@"application-identifier md5 is :%s",calcString_md5([@"7X6Q9L7U5D.com.chenxiancai.app" UTF8String]));
        // 3.计算bundleId
        NSLog(@"bundleId is :%s",calcString_md5([@"com.chenxiancai.app" UTF8String]));
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
#endif
    }
}


