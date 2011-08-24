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

#ifndef WEPATTACK_LOG_H
#define WEPATTACK_LOG_H

#include "wepattack.h"

extern char logfile[40];

//
// start logging an writes header to logfile
//
void open_log(char *word, char *in);

//
// log cracked bssid with additional information
//
void log_bssid(wlan_packet_list* bssid);

//
// log all uncracked networks
//
void log_uncracked(wlan_packet_list* list);

#endif
