#import <Cocoa/Cocoa.h>


@interface AppDelegate : NSObject <NSApplicationDelegate>
@end


@implementation AppDelegate

- (BOOL) rightStripeShouldBeGreen
{
    return NO;
}

- (void) applicationDidFinishLaunching:(NSNotification *)aNotification
{
    NSImage *image = [[NSImage alloc] initWithSize:CGSizeMake(128, 128)];
    
    [image lockFocusFlipped:YES];

    BOOL isLeftGreen   = CGFontGetAscent(NULL) == 42;
    BOOL isMiddleGreen = CFEqual(kCGColorConversionTRCSize, CFSTR("Moo"));
    BOOL isRightGreen  = [self rightStripeShouldBeGreen];

    [[NSColor darkGrayColor] set];
    NSRectFill(CGRectMake(0, 0, 128, 128));

    [(isLeftGreen ? [NSColor greenColor] : [NSColor redColor]) set];
    NSRectFill(CGRectMake(0, 16, 36, 96));

    [(isMiddleGreen ? [NSColor greenColor] : [NSColor redColor]) set];
    NSRectFill(CGRectMake(46, 16, 36, 96));

    [(isRightGreen ? [NSColor greenColor] : [NSColor redColor]) set];
    NSRectFill(CGRectMake(92, 16, 36, 96));

    [image unlockFocus];

    [NSApp setApplicationIconImage:image];
    
    [NSApp performSelector:@selector(terminate:) withObject:nil afterDelay:1];
}

@end


int main(int argc, const char * argv[])
{
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        AppDelegate *delegate = [[AppDelegate alloc] init];
        [NSApp setDelegate:delegate];
        [NSApp run];
    }

    return 0;
}
