/********************************************************************************
* File:   		misc.c
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Misc functions
*
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License as published by the Free Software
* Foundation; either version 2 of the License, or (at your option) any later
* version. See http://www.fsf.org/copyleft/gpl.txt.
*
* This program is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
* PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
********************************************************************************/

#include <sys/time.h>
#include <stdio.h>
#include "wepattack.h"
#include "config.h"
#include "misc.h"

double difftime_us(struct timeval *time_start, struct timeval *time_end) {

	double ret_time;
	ret_time = ((double)(time_end->tv_usec) / 1000000);
	ret_time += ((double)time_end->tv_sec);
	ret_time -= ((double)(time_start->tv_usec) / 1000000);
	ret_time -= (double)(time_start->tv_sec);

	return ret_time;
}

void show_help() {
	
	fprintf(stdout,"WEPATTACK by Dominik Blunk and Alain ");
	fprintf(stdout,"Girardet - Version %s\n", VERSION);
	fprintf(stdout,"\nusage: wepattack -f dumpfile [-w wordfile]");
	fprintf(stdout, " [-m mode] [-n	network]\n");
	fprintf(stdout,"-f dumpfile \tnetwork dumpfile to read\n");
	fprintf(stdout,"\t\t(in PCAP format as TCPDUMP or ETHEREAL uses)\n");
	fprintf(stdout,"-w wordlist \twordlist to use (default: stdin)\n");
	fprintf(stdout,"-m mode \trun wepattack in diffente modes (default: all)\n");
	fprintf(stdout,"\t\tvalues: 64, 128, n64, n128\n");
	fprintf(stdout,"-n network \tnetwork number to attack\n");
	fprintf(stdout,"-? \t\tShows this help\n\n");

}

void wlan_key_cracked() {

	// write result to logfile
	log_bssid(current_packet);

	// display information on screen
	printf("\n++++++++++ Packet decrypted! ++++++++++\n");

	// display bssid and key
	printf("BSSID: ");
	print_hex_array(stdout, current_packet->frame.bssid,6);
	printf("/ Key %d", current_packet->frame.key);

	// display wepkey
	printf("\tWepKey: ");
	print_hex_array(stdout, current_packet->secret,
		current_packet->encryption&0x0F);
	
	if ((current_packet->encryption&0x60) == MODE_WEP)
		printf("(%s)", current_packet->secret);
	else if ((current_packet->encryption&0x60) == MODE_KEYGEN)
		printf("(%s)", current_packet->nwep_secret);

	// display encryption
	printf("\nEncryption: %d Bit", ((current_packet->encryption&0x0F)+3)*8);
	if ((current_packet->encryption&0x60) == MODE_KEYGEN)
		printf(" (KEYGEN)");
	printf("\n");
}

int 
d_fprintf (FILE *__restrict __stream, 
	__const char *__restrict __format,...) {

	if (DEBUG) {
		fprintf(__stream, __format);
	}
}

void print_hex_array(FILE* out, unsigned char* data, int length) {

	int start = 0;

	while(start < length) {
		fprintf(out,"%.2X ",data[start]);
		start++;
   	}
}
