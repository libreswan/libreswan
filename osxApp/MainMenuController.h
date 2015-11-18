//
//  MainMenuController.h
//  Libreswan
//
//  Created by Jose Quaresma on 11/6/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Growl-WithInstaller/Growl.h>
#import "ConnectionsDB.h"
#include <unistd.h>
#include <netinet/in.h>
#include "BetterAuthorizationSampleLib.h"
#include "Common.h"

@class AdvMenuController;
@class PreferenceController;

static AuthorizationRef gAuth;

@interface MainMenuController : NSWindowController <GrowlApplicationBridgeDelegate> {
	AdvMenuController* advMenuController;
	PreferenceController *preferenceController;

	ConnectionsDB* db;

	IBOutlet NSView* discView;
	IBOutlet NSView* connView;
	IBOutlet NSPopUpButton* selConn;

	NSDate* connTime;
	NSTimer* timer;
	NSTimeInterval connDuration;
	NSMutableString* connDurationPrint;
}

@property (readwrite, retain) NSPopUpButton* selConn;
@property (readwrite, retain) ConnectionsDB* db;
@property (readwrite, retain) NSDate* connTime;
@property (readwrite, retain) NSMutableString* connDurationPrint;
@property (readwrite) NSTimeInterval connDuration;
@property (nonatomic, assign) NSTimer* timer;

- (IBAction)showPreferencePanel: (id)sender;
- (IBAction)showAdvMenu: (id)sender;
- (IBAction)connDisc: (id) sender;

- (NSString *) pathForDataFile;
- (void) saveDataToDisk;
- (void) loadDataFromDisk;
- (IBAction)saveData: (id)sender;
- (IBAction)loadData: (id)sender;

- (void)updateConnDuration: (NSTimer*)aTimer;
- (IBAction)connect: (id)sender;

- (void) saveConnToFile;

//Growl
- (NSDictionary*) registrationDictionaryForGrowl;

@end
