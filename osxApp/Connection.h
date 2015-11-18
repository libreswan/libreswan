//
//  Connection.h
//  Libreswan
//
//  Created by Jose Quaresma on 26/5/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>


@interface Connection : NSObject <NSCoding> {

	NSMutableString* connName;

	//Connection Options
	NSMutableString* selAuto;
	NSMutableString* selType;
	NSMutableString* selMode;

	NSMutableString* selLocalHost;
	NSMutableString* selLocalID;
	NSMutableString* selLocalSubnets;
	NSMutableString* selLocalProtocolPort;

	NSMutableString* selRemoteHost;
	NSMutableString* selRemoteID;
	NSMutableString* selRemoteSubnets;
	NSMutableString* selRemoteProtocolPort;

	//Auth Options
	NSMutableString* selAuthBy;
	NSMutableString* selPSK;
	NSMutableString* selPKCS;
	NSMutableString* selSendCert;
	NSMutableString* selLocalRSASigKey;
	NSMutableString* selRemoteRSASigKey;

	//Global Options
	NSButton* selNatTEnable;
	NSMutableString* selVirtualPrivate;
	NSMutableString* selForceKeepAlive;
	NSMutableString* selKeepAlive;
	NSButton* selForceEncaps;

	NSMutableString* selCrlCheckIntvl;
	NSButton* selStrictCrlEnable;

	NSButton* selOppEncEnable;
	NSMutableString* selMyID;

	NSMutableString* selPlutoDebug;
	NSButton* selUniqueIDs;

	//Advanced Options
	NSButton* selDPDEnable;
	NSMutableString* selDPDDelay;
	NSMutableString* selDPDTimeout;
	NSMutableString* selDPDAction;

	NSMutableString* selIKE1Enc;
	NSMutableString* selIKE1Hash;
	NSMutableString* selIKE2Enc;
	NSMutableString* selIKE2Hash;

	NSMutableString* selIKEv2;
	NSMutableString* selIKELifetime;

	NSButton* selCompressEnable;
	NSButton* selPfsEnable;
	NSButton* selRekeyEnable;

	NSMutableString* selPhase2;
	NSMutableString* selPhase2Alg;
	NSMutableString* selSALifetime;
	NSMutableString* selRekeyMargin;
	NSMutableString* selRekeyFuzz;
	NSMutableString* selKeyingTries;

	NSButton* selLocalXauthServer;
	NSButton* selLocalXauthClient;
	NSButton* selLocalModeCfgServer;
	NSButton* selLocalModeCfgClient;
	NSMutableString* selLocalXauthUsername;

	NSButton* selRemoteXauthServer;
	NSButton* selRemoteXauthClient;
	NSButton* selRemoteModeCfgServer;
	NSButton* selRemoteModeCfgClient;
	NSMutableString* selRemoteXauthUsername;

	NSMutableString* selModeCfgDNS1;
	NSMutableString* selModeCfgDNS2;
	NSMutableString* selModeCfgWins1;
	NSMutableString* selModeCfgWins2;

	NSButton* selModeCfgPullEnable;

	NSMutableString* selNHelpers;
	NSMutableString* selSyslog;
	NSMutableString* selPlutoOpts;
	NSMutableString* selPlutoStdErrLog;
	NSMutableString* selPlutoRestartOnCrash;
	NSMutableString* selNextHop;
	NSMutableString* selSourceIP;
	NSMutableString* selUpdownScript;

}

@property (readwrite, retain) NSMutableString *connName;
//Connection Options
@property (readwrite, retain) NSMutableString
*selAuto,
*selType,
*selMode,
*selLocalHost,
*selLocalID,
*selLocalSubnets,
*selLocalProtocolPort,
*selRemoteHost,
*selRemoteID,
*selRemoteSubnets,
*selRemoteProtocolPort;
//Auth Options
@property (readwrite, retain) NSMutableString
*selAuthBy,
*selPSK,
*selPKCS,
*selSendCert,
*selLocalRSASigKey,
*selRemoteRSASigKey;
//Global Options
@property (readwrite, retain) NSMutableString
*selVirtualPrivate,
*selForceKeepAlive,
*selKeepAlive,
*selCrlCheckIntvl,
*selMyID,
*selPlutoDebug;

@property (readwrite, retain) NSButton
*selForceEncaps,
*selNatTEnable,
*selStrictCrlEnable,
*selOppEncEnable,
*selUniqueIDs;

//Advanced Options
@property (readwrite, retain) NSMutableString
*selDPDDelay,
*selDPDTimeout,
*selDPDAction,
*selIKE1Enc,
*selIKE1Hash,
*selIKE2Enc,
*selIKE2Hash,
*selIKEv2,
*selIKELifetime,
*selPhase2,
*selPhase2Alg,
*selSALifetime,
*selRekeyMargin,
*selRekeyFuzz,
*selKeyingTries,
*selRemoteXauthUsername,
*selLocalXauthUsername,
*selModeCfgDNS1,
*selModeCfgDNS2,
*selModeCfgWins1,
*selModeCfgWins2,
*selNHelpers,
*selSyslog,
*selPlutoOpts,
*selPlutoStdErrLog,
*selPlutoRestartOnCrash,
*selNextHop,
*selSourceIP,
*selUpdownScript;

@property (readwrite, retain) NSButton
*selDPDEnable,
*selCompressEnable,
*selPfsEnable,
*selRekeyEnable,
*selLocalXauthServer,
*selLocalXauthClient,
*selLocalModeCfgServer,
*selLocalModeCfgClient,
*selRemoteXauthServer,
*selRemoteXauthClient,
*selRemoteModeCfgServer,
*selRemoteModeCfgClient,
*selModeCfgPullEnable;

@end
