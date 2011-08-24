/********************************************************************************
* File:   		wepfilter.h
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

#ifndef WEPATTACK_WEPFILTER_H
#define WEPATTACK_WEPFILTER_H

// struct for bssid list
typedef struct bssid_list bssid_list;
struct bssid_list {
	unsigned char bssid[6];
	int key;
	bssid_list* next;
};

// struct for parsing wlan packet
typedef struct packet_delimiter packet_delimiter;
struct packet_delimiter {
	int frame_control;
	int duration;
	int dst_address;
	int src_address;
	int bssid;
	int address4;
	int sequence_control;
	int iv;
	int key;
	int payload;
};

//
// get wlan packets from file, return is a list with all different bssid
// and keys
//
wlan_packet_list* get_packets(char* infile);

//
// get one bssid from a list
//
wlan_packet_list* get_one_packet(wlan_packet_list* head, unsigned char* bssid, int key);

//
// delete list (deallocate dynamic memory)
//
void delete_list(wlan_packet_list* list);

#endif
