//
//  MainMenuController.m
//  Libreswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "MainMenuController.h"
#import "AdvMenuController.h"
#import "PreferenceController.h"
#import "ConnectionsDB.h"
#import "Connection.h"
#import <AppKit/NSCell.h>

//Stuff from Libreswan
#define LIBRESWAN_COCOA_APP 1
#import <sys/queue.h>
#import "ipsecconf/confread.h"
#import "libreswan/passert.h"
#import "oswlog.h"
#import "programs/pluto/log.h"
void exit_tool(int x)
{
	exit(x);
}
char* progname = "libreswan \0";
int verbose=0;
int warningsarefatal = 0;
#import "ipsecconf/confwrite.h"


@implementation MainMenuController
@synthesize db, connTime, connDuration, timer, connDurationPrint, selConn;

- (IBAction)showAdvMenu: (id)sender
{
	//Is advMenuController nil?
	if(!advMenuController){
		advMenuController = [[AdvMenuController alloc] init];
		[advMenuController setSelItemIndex:[[self selConn] indexOfSelectedItem]];
	}
	else{
		[[advMenuController selConn] selectItemAtIndex:[[self selConn] indexOfSelectedItem]];
	}
	
	NSLog(@"Showing %@", advMenuController);
	[advMenuController showWindow: self];
}

- (IBAction)connDisc: (id) sender
{
	if([sender state] == NSOnState){
		[connView setHidden:YES];
		[discView setHidden:NO];
	}
	else{
		[connView setHidden:NO];
		[discView setHidden:YES];
	}
}

- (void)awakeFromNib
{
	[NSApp setDelegate: self];
	
	[GrowlApplicationBridge setGrowlDelegate:self];
	
	[self loadDataFromDisk];
	
	[connView setHidden:NO];
	[discView setHidden:YES];
	[self setConnDurationPrint:[NSString stringWithString:@"0:0:0"]];
}

- (void) applicationWillTerminate: (NSNotification *)note
{
	[self saveDataToDisk];
}

- (IBAction)showPreferencePanel: (id)sender
{
	//Is preferenceController nil?
	if(!preferenceController){
		preferenceController = [[PreferenceController alloc] init];
	}
	NSLog(@"Showing %@", preferenceController);
	[preferenceController showWindow: self];
}

#pragma mark archiving
- (NSString *) pathForDataFile
{
	NSFileManager *fileManager = [NSFileManager defaultManager];

	NSString *folder = @"~/Library/Application Support/Libreswan/";
	folder = [folder stringByExpandingTildeInPath];
	
	if ([fileManager fileExistsAtPath: folder] == NO)
	{
		[fileManager createDirectoryAtPath: folder attributes: nil];
	}

	NSString *fileName = @"Libreswan.data";
	return [folder stringByAppendingPathComponent:fileName];
}

- (void) saveDataToDisk
{
	NSLog(@"Saving data to disk");
	NSString* path = [self pathForDataFile];
	
	NSMutableDictionary* rootObject;
	rootObject = [NSMutableDictionary dictionary];

	[rootObject setValue:[self db] forKey:@"db"];
	[NSKeyedArchiver archiveRootObject:rootObject toFile:path];
}

- (void) loadDataFromDisk
{
	NSLog(@"Loading data from disk");
	NSString* path        = [self pathForDataFile];
	NSDictionary* rootObject;

	rootObject = [NSKeyedUnarchiver unarchiveObjectWithFile:path];
	[self setDb:[rootObject valueForKey:@"db"]];
	
	//If there is no previously saved data
	if(db==NULL)
	{
		[self setDb:[ConnectionsDB sharedInstance]];	
	}	
}

- (IBAction)saveData: (id)sender
{
	[self saveDataToDisk];
}
- (IBAction)loadData: (id)sender
{
	[self loadDataFromDisk];
}

//Helper Tool

static OSStatus DoConnect(CFStringRef reqConnName)
// This code shows how to do a typical BetterAuthorizationSample privileged operation
// in straight C.  In this case, it does the low-numbered ports operation, which
// returns three file descriptors that are bound to low-numbered TCP ports.
{
    OSStatus        err;
    CFBundleRef     bundle;
    CFStringRef     bundleID;
    CFIndex         keyCount;
    CFStringRef     keys[2];
    CFTypeRef       values[2];
    CFDictionaryRef request;
    CFDictionaryRef response;
    BASFailCode     failCode;

    // Pre-conditions

	
    // Get our bundle information.

    bundle = CFBundleGetMainBundle();
    assert(bundle != NULL);

    bundleID = CFBundleGetIdentifier(bundle);
    assert(bundleID != NULL);

    // Create the request.  The request always contains the kBASCommandKey that
    // describes the command to do.  It also, optionally, contains the
	// kSampleLowNumberedPortsForceFailure key that tells the tool to always return
	// an error.  The purpose of this is to test our error handling path (do we leak
	// descriptors, for example).

    keyCount = 0;
    keys[keyCount]   = CFSTR(kBASCommandKey);
    values[keyCount] = CFSTR(kConnectCommand);
    keyCount += 1;
	
	keys[keyCount]   = CFSTR("connName");
    values[keyCount] = CFStringCreateCopy(NULL, reqConnName);
    keyCount += 1;
	
    request = CFDictionaryCreate(
								 NULL,
								 (const void **) keys,
								 (const void **) values,
								 keyCount,
								 &kCFTypeDictionaryKeyCallBacks,
								 &kCFTypeDictionaryValueCallBacks
								 );
    assert(request != NULL);

    response = NULL;

    // Execute it.
	
	err = BASExecuteRequestInHelperTool(
										gAuth,
										kCommandSet,
										bundleID,
										request,
										&response
										);
	
    // If it failed, try to recover.
	
    if ( (err != noErr) && (err != userCanceledErr) ) {
        int alertResult;

        failCode = BASDiagnoseFailure(gAuth, bundleID);

        // At this point we tell the user that something has gone wrong and that we need
        // to authorize in order to fix it.  Ideally we'd use failCode to describe the type of
        // error to the user.
		
        alertResult = NSRunAlertPanel(@"Needs Install", @"BAS needs to install", @"Install", @"Cancel", NULL);

        if ( alertResult == NSAlertDefaultReturn ) {
            // Try to fix things.

            err = BASFixFailure(gAuth, (CFStringRef) bundleID, CFSTR("InstallTool"), CFSTR("HelperTool"), failCode);
			
            // If the fix went OK, retry the request.

            if (err == noErr) {
                err = BASExecuteRequestInHelperTool(
													gAuth,
													kCommandSet,
													bundleID,
													request,
													&response
													);
            }
        } else {
            err = userCanceledErr;
        }
    }
	
    // If all of the above went OK, it means that the IPC to the helper tool worked.  We
    // now have to check the response dictionary to see if the command's execution within
    // the helper tool was successful.

    if (err == noErr) {
        err = BASGetErrorFromResponse(response);
    }

    // Extract the descriptors from the response and copy them out to our caller.

    if (err == noErr) {
		CFStringRef returnString;
		
		returnString = (CFStringRef) CFDictionaryGetValue(response, CFSTR(kBASTestString));
		NSLog(@"Command ran: %@", returnString);
    }
		

    if (response != NULL) {
        CFRelease(response);
    }

    return err;
}

- (IBAction)connect: (id)sender
{	
	if([self timer] == nil) {
		[self setConnTime:[NSDate date]];
		
		NSTimer *tmpTimer = [NSTimer scheduledTimerWithTimeInterval:1
															 target:self
														   selector:@selector(updateConnDuration:)
														   userInfo:nil
															repeats:YES];
		[self setTimer:tmpTimer];
	}
	else {
		[[self timer] invalidate];
		//[[self timer] release];
		[self setTimer:nil];
		[self setConnDuration:0];
		[self setConnDurationPrint:[NSString stringWithString:@"0:0:0"]];
	}
	if([sender state] == NSOnState){
		[connView setHidden:YES];
		[discView setHidden:NO];
		
		[self saveConnToFile];
		
		///////////////
		OSStatus    err;
		
		// Call the C code to do the real work.
		
		Connection *conn = [[[ConnectionsDB sharedInstance] connDB] objectAtIndex:[selConn indexOfSelectedItem]];
		
		char connName[100];
		[[conn connName] getCString:connName maxLength:100 encoding:NSMacOSRomanStringEncoding];
		
		CFStringRef reqConnName = CFStringCreateWithCString(NULL, connName, CFStringGetSystemEncoding());
		
		err = DoConnect(reqConnName);
		
		// Log our results.

		
		
		//////////////
		
		[GrowlApplicationBridge
		 notifyWithTitle:@"Connected"
		 description:@"Connection was established"
		 notificationName:@"Libreswan Growl Notification"
		 iconData:nil
		 priority:0
		 isSticky:NO
		 clickContext:nil];
	}
	else{
		[connView setHidden:NO];
		[discView setHidden:YES];
		
		//Delete conn file?
		/*
		Connection *conn = [[[ConnectionsDB sharedInstance] connDB] objectAtIndex:[selConn indexOfSelectedItem]];
		NSString *origFileName = [conn connName];
		NSString *fileName = [origFileName stringByAppendingFormat:@".conf"];
		NSString *origPath = @"~/Library/Application Support/Libreswan";
		NSString *filePath = [origPath stringByAppendingPathComponent:fileName];
		NSString *path = [filePath stringByStandardizingPath];
		
		NSFileManager *fileManager = [NSFileManager defaultManager];
		if ([fileManager fileExistsAtPath: path] == YES)
		{
			[fileManager removeFileAtPath:path handler:nil];
		}
		*/
		
		[GrowlApplicationBridge
		 notifyWithTitle:@"Disconnected"
		 description:@"Connection was closed"
		 notificationName:@"Libreswan Growl Notification"
		 iconData:nil
		 priority:0
		 isSticky:NO
		 clickContext:nil];
	}
}

- (void)updateConnDuration: (NSTimer*)aTimer
{
	NSDate* now = [NSDate date];
	[self setConnDuration:[now timeIntervalSinceDate: connTime]];
	int hours = (NSInteger)connDuration / 3600;
	[self setConnDuration:(NSInteger)connDuration % 3600];
	int mins = (NSInteger)connDuration / 60;
	[self setConnDuration:(NSInteger)connDuration % 60];
	int secs = (NSInteger)connDuration;
	[self setConnDurationPrint:[NSString stringWithFormat:@"%d:%d:%d", hours, mins, secs]];
}

//Growl
- (NSDictionary*)registrationDictionaryForGrowl
{
	NSArray *notifications;
	notifications = [NSArray arrayWithObject:@"Libreswan Growl Notification"];
	
	NSDictionary *dict;
	dict = [NSDictionary dictionaryWithObjectsAndKeys:
			notifications, GROWL_NOTIFICATIONS_ALL,
			notifications, GROWL_NOTIFICATIONS_DEFAULT, nil];
	
	return dict;
}

int main(int argc, char *argv[])
{
    OSStatus    junk;

    // Create the AuthorizationRef that we'll use through this application.  We ignore
    // any error from this.  A failure from AuthorizationCreate is very unusual, and if it
    // happens there's no way to recover; Authorization Services just won't work.
	
    junk = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &gAuth);
    assert(junk == noErr);
    assert( (junk == noErr) == (gAuth != NULL) );
	
	// For each of our commands, check to see if a right specification exists and, if not,
    // create it.
    //
    // The last parameter is the name of a ".strings" file that contains the localised prompts
    // for any custom rights that we use.

	BASSetDefaultRules(
					   gAuth,
					   kCommandSet,
					   CFBundleGetIdentifier(CFBundleGetMainBundle()),
					   CFSTR("AuthorizationPrompts")
					   );

    return NSApplicationMain(argc,  (const char **) argv);
}

#pragma mark writeFile
- (void) saveConnToFile {
	struct starter_config *cfg = NULL;
	struct starter_conn *new_conn = NULL;
	err_t perr = NULL;
	FILE *file = NULL;
	
	char *cPath = "../../test/testGUI.cfg";
	
	//Connection *conn = [[[ConnectionsDB sharedInstance] connDB] objectAtIndex:[selConn indexOfSelectedItem]];
	
	//file pathname
	/*
	 NSString *origFileName = [conn connName];
	 NSString *fileName = [origFileName stringByAppendingFormat:@".conf"];
	 NSString *origPath = @"~/Library/Application Support/Libreswan";
	 NSString *filePath = [origPath stringByAppendingPathComponent:fileName];
	 NSString *path = [filePath stringByStandardizingPath];
	 char cPath[100];
	 [path getCString:cPath maxLength:100 encoding:NSMacOSRomanStringEncoding];
	 */
	
	cfg = (struct starter_config *) malloc(sizeof(struct starter_config));
	if (!cfg) printf("can't allocate memory");
	
	memset(cfg, 0, sizeof(struct starter_config));
	
	ipsecconf_default_values(cfg);
	
	//NSString to char*
	//char cConnName[20];
	//[[conn connName] getCString:cConnName maxLength:20 encoding:NSMacOSRomanStringEncoding];
	
	new_conn = alloc_add_conn(cfg, "test", &perr);
	if(new_conn == NULL) printf("%s", perr);
	
	cfg->setup.options_set[KBF_NATTRAVERSAL] = 1;
	cfg->setup.options[KBF_NATTRAVERSAL] = 0;
	
	cfg->setup.strings_set[KSF_PROTOSTACK] = 1;
	cfg->setup.strings[KSF_PROTOSTACK] = strdup("netkey");
	
	new_conn->connalias = strdup("anotheralias");
	
	new_conn->left.rsakey2 = (unsigned char *)"0s23489234ba28934243";
    new_conn->left.rsakey1 = (unsigned char *)"0sabcdabcdabcd";
	
	new_conn->desired_state = STARTUP_START;
	
	new_conn->options_set[KBF_AUTO] = 1;
	new_conn->options[KBF_AUTO] = STARTUP_START;
	
	new_conn->left.cert = "/my/cert/file";
	
	file = fopen(cPath,"w");
	confwrite(cfg, file);
	fclose(file); 	
}


@end
