/********************************************************************************
* File:   		wepfilter.c
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Read network dump file (PCAP-format) and extracts
* encrypted 802.11 DATA packets
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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include "rc4.h"
#include "wepattack.h"
#include "wepfilter.h"
#include "config.h"
#include "misc.h"

static int capture_successfull = 0;
static wlan_packet_list* head = NULL;

//
// puts new bssid at the beginning of the list (pointed by bssid_head)
//
void push_bssid(bssid_list** head, u_char* bssid, int key) {
	bssid_list* newbssid = malloc(sizeof(bssid_list));
	memcpy(newbssid->bssid, bssid, 6);
	newbssid->key = key;
	newbssid->next = *head;
	*head = newbssid;
}

//
// Checks if bssid is already in list (that means that one packet of
// this network is already captured)
//
int check_bssid(bssid_list* head, unsigned char* bssid, int key) {

	while(head != NULL) {

		if((memcmp(head->bssid, bssid, 6) == 0) && (head->key == key))
			return 1;

		head = head->next;
	}

	return 0;
}

//
// extracts 1 element of list and deletes all other elements
//
wlan_packet_list* get_one_packet(wlan_packet_list* head, unsigned char* bssid,
int key) {

	wlan_packet_list* last_packet = NULL;
	while(head != NULL) {

		if((memcmp(head->frame.bssid, bssid, 6) == 0) && (head->frame.key == key)) {
			last_packet = head->next->next;
			head->next->next = NULL;
			delete_list(last_packet);
			return head;
		}

		last_packet = head;
		head = head->next;
		free(last_packet);
	}
}

//
// puts new element at the beginning of the list (pointed by head)
//
void push(wlan_packet_list** head, const u_char* data, int length,
packet_delimiter limits) {

	wlan_packet_list* newframe = malloc(sizeof(wlan_packet_list));
	memcpy(&newframe->frame.frameControl, data+limits.frame_control, 2);
	memcpy(&newframe->frame.duration, data+limits.duration, 2);
	memcpy(&newframe->frame.srcAddress, data+limits.src_address, 6);
	memcpy(&newframe->frame.dstAddress, data+limits.dst_address, 6);
	memcpy(&newframe->frame.bssid, data+limits.bssid, 6);

	if(limits.address4 > 0) {
		memcpy(&newframe->frame.address4, data+limits.address4, 6);
	}
	memcpy(&newframe->frame.sequenceControl, data+limits.sequence_control, 2);
	memcpy(&newframe->frame.iv, data+limits.iv, 3);
	memcpy(&newframe->frame.key, data+limits.key, 1);
	newframe->frame.key = newframe->frame.key >> 6;
	memcpy(&newframe->frame.payload, data+limits.payload, length-limits.payload);
	newframe->framesize = length;
	newframe->next = *head;
	*head = newframe;
}

//
// callback function that is passed to pcap_loop() and called each time a
// packet is recieved
//
void my_callback(u_char *useless, const struct pcap_pkthdr* pkthdr,
	const u_char* packet) {

    static int count = 1;
    FILE *fp;
    unsigned int framesize = pkthdr->caplen;
    static bssid_list* head_bssid = NULL;
    unsigned char bssid[6];
    int key;
    static packet_delimiter limits;

    if(pkthdr->len != pkthdr->caplen) {
    	fprintf(stdout,"\nWARNING: Framesize (%d) and captured frame length (%d) not equal!",
		pkthdr->len, pkthdr->caplen);
    }

    if((packet[0] == 0x08) || (packet[0] == 0x88) 
    	|| (packet[0] == 0x48) || (packet[0] == 0xC8)) {

	d_fprintf(stdout, "\nFrame is a 802.11 DATA frame");

 	if((packet[1] & 0x43) == 0x40) {
		// Data frame 0 [STA - STA within same IBSS (no acces to DS -> no AP)]
		// (To DS = 0 / From DS = 0)
		d_fprintf(stdout, "\nFrame is of type 0\n");
		limits.frame_control = 0;
		limits.duration = 2;
		limits.src_address = 10;
		limits.dst_address = 4;
		limits.bssid = 16;
		limits.address4 = -1;
		limits.sequence_control = 22;
		limits.iv = 24;
		limits.key = 27;
		limits.payload = 28;
	}
	else if((packet[1] & 0x43) == 0x42) {
		// Data frame 1 [Frame exiting DS] (To DS = 0 / From DS = 1)
		d_fprintf(stdout, "\nFrame is of type 1\n");
		limits.frame_control = 0;
		limits.duration = 2;
		limits.src_address = 16;
		limits.dst_address = 4;
		limits.bssid = 10;
		limits.address4 = -1;
		limits.sequence_control = 22;
		limits.iv = 24;
		limits.key = 27;
		limits.payload = 28;
	}
	else if((packet[1] & 0x43) == 0x41) {
 		// Data frame 2 [Frame destined for DS] (To DS = 1 / From DS = 0)
		d_fprintf(stdout, "\nFrame is of type 2\n");
		limits.frame_control = 0;
		limits.duration = 2;
		limits.src_address = 10;
		limits.dst_address = 16;
		limits.bssid = 4;
		limits.address4 = -1;
		limits.sequence_control = 22;
		limits.iv = 24;
		limits.key = 27;
		limits.payload = 28;
		//j = 1;
	}
	else if((packet[1] & 0x43) == 0x43) {
		// Data frame 3 [AP - AP (WDS)] (To DS = 1 / From DS = 1)
		d_fprintf(stdout, "\nFrame is of type 3\n");
		limits.frame_control = 0;
		limits.duration = 2;
		limits.src_address = 24;
		limits.dst_address = 16;
		limits.bssid = 10;
		limits.address4 = 4;
		limits.sequence_control = 22;
		limits.iv = 30;
		limits.key = 33;
		limits.payload = 34;
	}
	else {
		return;
	}

	// Pad != 0? Capture problem with some wlan cards (prism chipset?)
	if((packet[limits.key] & 0x3f) != 0x00) {
		fprintf(stdout, "\nWARNING: Pad is not 0 -> there might be a capture ");
		fprintf(stdout, "problem (does your card support true promiscious mode?)!");
	}
	else {
		memcpy(bssid, packet+limits.bssid, 6);
		//packet[limits.key] = packet[limits.key]>>6;
		key = packet[limits.key]>>6;

		if(!check_bssid(head_bssid, bssid, key)) {

			d_fprintf(stdout, "Capture packet-> BSSID: ", *bssid);

			// BSSID is not known -> add packet to list
			push(&head, packet, framesize, limits);

			// Add BSSID to list
			push_bssid(&head_bssid, bssid, key);
			capture_successfull = 1;
		}
	}

    }
    else {
	d_fprintf(stdout, "\nNo 802.11 DATA frame");
    }

    count++;
}

//
// Returns pointer of packet list
//
wlan_packet_list* get_packets(char* infile) {

	int packet_cnt = -1;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
    	const u_char *packet;
    	struct pcap_pkthdr hdr;     	// pcap.h

	// List (last element is always empty)
	head = malloc(sizeof(wlan_packet_list));
	head->next = NULL;

	//descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
   	descr = pcap_open_offline(infile, errbuf);
    	if(descr == NULL) {
    		printf("\npcap_open_offline(): %s",errbuf);
		exit(1);
    	}

	// Here we stay in a loop until all packets are processed
	// For each packet function my_callback() is fired
    	pcap_loop(descr, packet_cnt, my_callback, NULL);

    	if(capture_successfull == 1) {
		fprintf(stdout, "\nExtraction of necessary data was successfull!");
		return head;
    	}
    	else {
    		fprintf(stdout, "\nERROR: No encrypted 802.11 DATA frames captured!");
		fprintf(stdout, "\nTry again with other dump file!\n");
		return NULL;
    	}
}

//
// delete list (deallocate dynamic memory)
//
void delete_list(wlan_packet_list* list) {

wlan_packet_list* temp;

	while (list != NULL) {
		temp = list;
		list = list->next;
		free(temp);
	}
}
