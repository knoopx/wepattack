/********************************************************************************
* File:   		rc4.h
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Implementation of RC4 algorithm
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

#ifndef WEPATTACK_RC4_H
#define WEPATTACK_RC4_H

typedef struct rc4_key rc4_key;
struct rc4_key
{
     unsigned char state[256];
     unsigned char x;
     unsigned char y;
};

//
// prepare key for rc4, do not proceed rc4 twice with the same prepared
// key! it will no produce an equivalent result because of the
// initialisatio of the key
//
void prepare_key(unsigned char *key_data_ptr,int key_data_len,rc4_key *key);

//
// applies rc4 on specified buffer
//
void rc4(unsigned char *buffer_ptr,int buffer_len,rc4_key * key);

#endif
