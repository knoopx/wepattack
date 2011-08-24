/********************************************************************************
* File:   		log.c
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Write attack result to logfile
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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "log.h"
#include "wepattack.h"
#include "config.h"

static time_t start_time;
char logfile[40];

//
// generate logfile name, logfiles wouldn't be overwritten
//
void get_logfile(char *name) {

	FILE* fp;
	time_t now;
	struct tm* date;
	int file_count = 1;

	now = time(&now);
	date = localtime(&now);

	// generate first logfile name
	sprintf(name,"%s-%d-%.2d-%.2d-%d%s", LOGFILE_PREFIX, date->tm_year+1900,
		date->tm_mon+1, date->tm_mday, file_count, LOGFILE_POSTFIX);

	// try to open file, file does exist, if open is successful
	fp = fopen(name,"r");

	// loop until file open fail (file does not exist)
	while (fp != NULL) {
		file_count++;
		fclose(fp);
		sprintf(name,"%s-%d-%.2d-%.2d-%d%s", LOGFILE_PREFIX, 
			date->tm_year+1900, date->tm_mon+1, date->tm_mday,
			file_count, LOGFILE_POSTFIX);
		fp = fopen(name,"r");
	}
}

void open_log(char *word, char *in) {

	FILE *fp;

	get_logfile(logfile);

	fp = fopen(logfile,"w");

	start_time = time(&start_time);
	fprintf(fp, "Logfile of WepAttack by Dominik Blunk and Alain Girardet\n\n");
	fprintf(fp, "Cracking started: %s", ctime(&start_time));
	fprintf(fp, "%s\t%s\n", word, in);

	fprintf(fp, "\nBssid\tKeyNo\tWepKey\tASCII\tEncryption\tElapsed Time");
	fclose(fp);
}

void log_bssid(wlan_packet_list* bssid) {

	FILE *fp;
	time_t now;
	int encryption;

	fp = fopen(logfile,"a");
	now = time(&now);

	fprintf(fp, "\n");
	print_hex_array(fp, bssid->frame.bssid,6);
	fprintf(fp, "\t%d", bssid->frame.key);

	fprintf(fp, "\t");

	print_hex_array(fp, bssid->secret, bssid->encryption&0x0F);
	if ((bssid->encryption&0x60) == MODE_WEP)
		fprintf(fp, "\t%s", bssid->secret);
	else if ((bssid->encryption&0x60) == MODE_KEYGEN)
		fprintf(fp, "\t%s", bssid->nwep_secret);

	fprintf(fp, "\t%d Bit", ((bssid->encryption&0x0F)+3)*8);
	if ((bssid->encryption&0x60) == MODE_KEYGEN)
		fprintf(fp, " (KEYGEN)");

	fprintf(fp, "\t%d sec", (int)difftime(now, start_time));

	fclose(fp);
}

void log_uncracked(wlan_packet_list* list) {

	FILE *fp;
	time_t now;

	fp = fopen(logfile,"a");
	now = time(&now);

	while (list->next != NULL) {
		if (!list->cracked) {
			fprintf(fp, "\n");
			print_hex_array(fp, list->frame.bssid, 6);
			fprintf(fp, "\t%d", list->frame.key);
			fprintf(fp, "\tnot cracked\t\t%d sec",
				(int)difftime(now, start_time));
		}
		list = list->next;
	}

	fprintf(fp,"\n");
	fclose(fp);
}
