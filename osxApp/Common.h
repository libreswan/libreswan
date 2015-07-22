/*
 *  Common.h
 *  Libreswan
 *
 *  Created by Jose Quaresma on 8/7/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

#ifndef _COMMON_H
#define _COMMON_H

#include "BetterAuthorizationSampleLib.h"

/////////////////////////////////////////////////////////////////

// Commands supported


// "LowNumberedPorts" asks the helper tool to open some low-numbered ports on our behalf.

#define kConnectCommand		"Connect"

// authorization right name

#define	kConnectRightName	"com.xelerance.libreswan.Connect"

// request keys

#define kSampleLowNumberedPortsForceFailure	"ForceFailure"              // CFBoolean (optional, presence implies true)

// response keys (none, descriptors for the ports are in kBASDescriptorArrayKey,
// the number of descriptors should be kNumberOfLowNumberedPorts)

#define kNumberOfLowNumberedPorts			3

// The kSampleCommandSet is used by both the app and the tool to communicate the set of
// supported commands to the BetterAuthorizationSampleLib module.

extern const BASCommandSpec kCommandSet[];

#endif

