/********************************************************************************
* File:   		verify.h
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Verify CRC und SNAP Header on byte stream
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

#ifndef WEPATTACK_VERIFY_H
#define WEPATTACK_VERIFY_H

//
// calculate crc32 over data and compares with crc
//
int verify_crc32(unsigned char *data, int length, unsigned long* crc);

//
// verify if first byte of data is 0xAA
//
int verify_snap(unsigned char *data);

#endif
