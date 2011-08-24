/********************************************************************************
* File:   		modes.h
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Implementation of attack modes (wep 64 bit,
* wep 128 bit, keygen 64 bit, keygen 128)
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

#ifndef WEPATTACK_MODES_H
#define WEPATTACK_MODES_H

//
// try to decrypt current packet with key, return is true if key match.
// function uses keygen to hash key
// generate_length: 5 or 13 for wep key length
//
int mode_keygen(const unsigned char *key, int key_length, int generate_length);

//
// try to decrypt current packet with key, return is true if key match.
// function uses cleat ascii mapping to key
// generate_length: 5 or 13 for wep key length
//
int mode_wep(const unsigned char *key, int key_length, int generate_length);

#endif
