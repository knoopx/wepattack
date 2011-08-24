/********************************************************************************
* File:   		wepattack.h
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Read guessed passwords from stdin and applies RC4
* on sniffed encrypted 802.11 DATA packets

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

#ifndef WEPATTACK_WEPATTACK_H
#define WEPATTACK_WEPATTACK_H

#include "rc4.h"

/*
 * struct for wlan packet
 */
typedef struct wlan_packet wlan_packet;
struct wlan_packet {
	unsigned char frameControl[2];
	unsigned char duration[2];
	unsigned char dstAddress[6];
	unsigned char srcAddress[6];
	unsigned char bssid[6];
	unsigned char address4[6];
	unsigned char sequenceControl[2];
	unsigned char iv[3];
	unsigned char key;
	unsigned char payload[2400];
};

/*
 * struct for wlan packet list incl. additional
 * informations
 */
typedef struct wlan_packet_list wlan_packet_list;
struct wlan_packet_list {
	wlan_packet frame;
	int framesize;
	unsigned char cracked;
	unsigned char secret[20];
	unsigned char nwep_secret[20];
	unsigned char encryption;
	wlan_packet_list* next;
};

// global pointer to current wlan packet
extern 	wlan_packet_list* 	current_packet;

#endif
