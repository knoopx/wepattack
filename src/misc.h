/********************************************************************************
* File:   		misc.h
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

#ifndef WEPATTACK_MISC_H
#define WEPATTACK_MISC_H

//
// calculate time in sec between to times, result fit microsec
//
double difftime_us(struct timeval *time_start, struct timeval *time_end);

//
// display help for comand line options
//
void show_help();

//
// display about current cracked wlan packet
//
void wlan_key_cracked();

//
// debug function, print to stream if debug flag in config.h is set
//
int d_fprintf (FILE *__restrict __stream, __const char *__restrict __format, ...);

//
// print string in hex to out-stream
//
void print_hex_array(FILE* out, unsigned char* data, int length);

#endif
