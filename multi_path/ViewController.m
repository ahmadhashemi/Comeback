//
//  ViewController.m
//  multi_path
//
//  Created by Ian Beer on 5/28/18.
//  Copyright © 2018 Ian Beer. All rights reserved.
//

#import "ViewController.h"

#include "sploit.h"
#include "jelbrek/jelbrek.h"
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/spawn.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <sys/dirent.h>
#include "utilities.h"

mach_port_t taskforpidzero;

uint64_t find_kernel_base() {
#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000
#define KERNEL_SEARCH_ADDRESS_IOS9 0xffffff8004004000
#define KERNEL_SEARCH_ADDRESS_IOS 0xffffff8000000000
    
#define ptrSize sizeof(uintptr_t)
    
    uint64_t addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(taskforpidzero, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(taskforpidzero, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(taskforpidzero, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    
                    printf("kernel base: 0x%llx\nkaslr slide: 0x%llx\n", addr, addr - 0xfffffff007004000);
                    
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
}

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    
    [super viewDidLoad];
    
}

- (IBAction)go:(id)sender {
    
    taskforpidzero = go();
    
    if (taskforpidzero == MACH_PORT_NULL) {
        
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Exploit Failed" message:@"Reboot your device and try again" preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction *defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {}];
        
        [alert addAction:defaultAction];
        
        [self presentViewController:alert animated:YES completion:nil];
        
        return;
    }
    
    init_jelbrek(taskforpidzero, find_kernel_base());
    [self jelbreak];
    
}

- (void)jelbreak {
    
    get_root(getpid());
    empower(getpid());
    unsandbox(getpid());
    
    if (geteuid() != 0) {
        
        UIAlertController* alert = [UIAlertController alertControllerWithTitle:@"Failed To Get Root" message:@"Reboot your device and try again" preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction* defaultAction = [UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:^(UIAlertAction * action) {}];
        
        [alert addAction:defaultAction];
        
        [self presentViewController:alert animated:YES completion:nil];
        
        return;
        
    }
    
    // if we reach here, everything is ok. do the job.
    
    [self disablePowerLimiter];
    
}

- (void)disablePowerLimiter {
    
    dispatch_async(dispatch_get_main_queue(), ^{
        
        NSArray *directoryFiles = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/System/Library/Watchdog/ThermalMonitor.bundle/" error:nil];
        NSArray *bundles = [directoryFiles filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"self ENDSWITH '.bundle'"]];
        
        for (NSString *bundle in bundles) {
            
            NSString *plistPath = [bundle stringByAppendingPathComponent:@"/Info.plist"];
            
            NSMutableDictionary *plistDictionary = [[NSMutableDictionary alloc] initWithContentsOfFile:[@"/System/Library/Watchdog/ThermalMonitor.bundle/" stringByAppendingPathComponent:plistPath]];
            NSMutableDictionary *tempContextualDictionary = [plistDictionary objectForKey:@"contextualClampParams"];
            
            [tempContextualDictionary removeObjectsForKeys:@[@"lowParamsPeakPower",@"lowParamsSpeaker",@"lowParamsCPU",@"lowParamsGPU"]];
            
            [plistDictionary setObject:tempContextualDictionary forKey:@"contextualClampParams"];
            [plistDictionary writeToFile:[@"/System/Library/Watchdog/ThermalMonitor.bundle/" stringByAppendingString:plistPath] atomically:YES];
            
        }
        
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Done" message:@"Restart you device to take effect" preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addAction:[UIAlertAction actionWithTitle:@"Restart" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            
            reboot(0);
            
        }]];
        
        [self presentViewController:alert animated:YES completion:nil];
        
    });
}

@end
