//Stuff from Libreswan
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define LIBRESWAN_COCOA_APP 1
#import <sys/queue.h>
#import "ipsecconf/confread.h"
#import "libreswan/passert.h"
#import "oswlog.h"
#import "programs/pluto/log.h"

/* exit_tool() is needed if the library was compiled with DEBUG, even if we are not.
 * The odd-looking parens are to prevent macro expansion:
 * lswlog.h without DEBUG define a macro exit_tool().
 */
void (exit_tool)(int x)
{
	exit(x);
}

char* progname = "libreswan\0";

int warningsarefatal = 0;
#import "ipsecconf/confwrite.h"

int main(int argc, char *argv[])
{
	struct starter_config *cfg = NULL;
	struct starter_conn *new_conn = NULL;
	err_t perr = NULL;
	FILE *file = NULL;

	char *cPath = "./test.cfg";

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
	if (cfg == NULL) {
		printf("can't allocate memory");
		return 1
	}

	ipsecconf_default_values(cfg);

	//NSString to char*
	//char cConnName[20];
	//[[conn connName] getCString:cConnName maxLength:20 encoding:NSMacOSRomanStringEncoding];

	new_conn = alloc_add_conn(cfg, "test", &perr);
	if (new_conn == NULL)
		printf("%s", perr);

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

	return 0;
}
