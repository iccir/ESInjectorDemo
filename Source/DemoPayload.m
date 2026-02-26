#import <Foundation/Foundation.h>

#import <objc/objc.h>
#import <objc/runtime.h>
#import <CoreGraphics/CoreGraphics.h>


// ----------------------------------------------------------------------------

// Use dyld interposing to make CGFontGetAscent() always return 42
// DemoApp checks this to color the left stripe green

int MyCGFontGetAscent(CGFontRef font) { return 42; }

__attribute__((used, section("__DATA,__interpose"))) static struct {
	int (*MyCGFontGetAscent)(CGFontRef);
	int (*  CGFontGetAscent)(CGFontRef);
} CGFontGetAscent_overrides[] = {
    { MyCGFontGetAscent, CGFontGetAscent },
};


// ----------------------------------------------------------------------------

// Use dyld interposing to replace kCGColorConversionTRCSize with "Moo"
// DemoApp checks this to color the middle stripe green

const CFStringRef MyCGColorConversionTRCSize = CFSTR("Moo");

__attribute__((used, section("__DATA,__interpose"))) static struct {
	const void *MyCGColorConversionTRCSize;
	const void *kCGColorConversionTRCSize;
} kCGColorConversionTRCSize_overrides[] = {
    { &MyCGColorConversionTRCSize, &kCGColorConversionTRCSize },
};


// ----------------------------------------------------------------------------

// Use method swizzling to make -[AppDelegate rightStripeShouldBeGreen]
// return YES. DemoApp checks this to color the right stripe green.

@interface AppDelegate : NSObject
- (BOOL) rightStripeShouldBeGreen;
@end

@implementation NSObject (AppDelegateReplacements)
- (BOOL) AppDelegate_rightStripeShouldBeGreen_replacement { return YES; }
@end

__attribute__((constructor)) static void init(void) {
	unsetenv("DYLD_INSERT_LIBRARIES");
  
    fprintf(stdout, "Hello from DemoPayload's init() function\n");
  
    Class cls = NSClassFromString(@"AppDelegate");
    if (!cls) return;

    SEL selA = @selector(rightStripeShouldBeGreen);
    SEL selB = @selector(AppDelegate_rightStripeShouldBeGreen_replacement);

	Method methodA = class_getInstanceMethod(cls, selA);
	Method methodB = class_getInstanceMethod(cls, selB);
    if (!methodA || !methodB) return;

    class_addMethod(cls, selA, class_getMethodImplementation(cls, selA), method_getTypeEncoding(methodA));
    class_addMethod(cls, selB, class_getMethodImplementation(cls, selB), method_getTypeEncoding(methodB));
    method_exchangeImplementations(class_getInstanceMethod(cls, selA), class_getInstanceMethod(cls, selB));
}
