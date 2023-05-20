#include "symbols.h"
#include "api.h"
#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

unsigned long long GetModuleSize(char *filename, uint32_t fileoffset,
                                 unsigned long long defaultsize) {
  @autoreleasepool {
    NSString *filePath = [NSString stringWithUTF8String:filename];
    NSFileManager *fileManager = [NSFileManager defaultManager];

    if ([fileManager fileExistsAtPath:filePath]) {
      NSError *error = nil;
      NSDictionary *fileAttributes =
          [fileManager attributesOfItemAtPath:filePath error:&error];

      if (!error) {
        NSNumber *fileSizeNumber = [fileAttributes objectForKey:NSFileSize];
        long long fileSize = [fileSizeNumber longLongValue];
        NSLog(@"File size: %lld bytes", fileSize);
        return fileSize;
      } else {
        NSLog(@"Failed to get file attributes: %@", error.localizedDescription);
      }
    } else {
      NSLog(@"File does not exist");
    }
  }
  return 0x40000;
}
