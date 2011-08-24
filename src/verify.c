/********************************************************************************
* File:   		verify.c
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

#include <stdio.h>
#include <zlib.h>

int verify_crc32(unsigned char *data, int length, unsigned long* crc) {

	unsigned long crc_calc;

	crc_calc = crc32(0L, NULL, 0);
	crc_calc = crc32(crc_calc, data, length);

	if (crc_calc == *crc) {
		return 1;
	}

	return 0;
}

int verify_snap(unsigned char *data) {

	unsigned char snap_header[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00};

	if (!memcmp(data, snap_header, 1))
		return 1;

	return 0;
}
