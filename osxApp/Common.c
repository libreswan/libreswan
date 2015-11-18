/*
 *  Common.c
 *  Libreswan
 *
 *  Created by Jose Quaresma on 8/7/09.
 *  Copyright 2009 __MyCompanyName__. All rights reserved.
 *
 */

#include "Common.h"

/*
 I originally generated the "SampleAuthorizationPrompts.strings" file by running
 the following command in Terminal.  genstrings doesn't notice that the
 CFCopyLocalizedStringFromTableInBundle is commented out, which is good for
 my purposes.

 $ genstrings SampleCommon.c -o en.lproj

 CFCopyLocalizedStringFromTableInBundle(CFSTR("GetUIDsPrompt"),          "SampleAuthorizationPrompts", b, "prompt included in authorization dialog for the GetUIDs command")
 CFCopyLocalizedStringFromTableInBundle(CFSTR("LowNumberedPortsPrompt"), "SampleAuthorizationPrompts", b, "prompt included in authorization dialog for the LowNumberedPorts command")
 */

/*
 IMPORTANT
 ---------
 This array must be exactly parallel to the kSampleCommandProcs array
 in "SampleTool.c".
 */

const BASCommandSpec kCommandSet[] = {
{
kConnectCommand,						// commandName
kConnectRightName,						// rightName
"default",                              // rightDefaultRule    -- by default, you have to have admin credentials (see the "default" rule in the authorization policy database, currently "/etc/authorization")
"ConnectPrompt",						// rightDescriptionKey -- key for custom prompt in "SampleAuthorizationPrompts.strings
NULL                                    // userData
},

{
NULL,                                   // the array is null terminated
NULL,
NULL,
NULL,
NULL
}
};
