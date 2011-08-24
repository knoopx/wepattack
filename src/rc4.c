/********************************************************************************
* File:   		rc4.c
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

#include "rc4.h"

static void swap_byte(unsigned char *a, unsigned char *b) {

     unsigned char swapByte;

     swapByte = *a;
     *a = *b;
     *b = swapByte;
}

void prepare_key(unsigned char *key_data_ptr, int key_data_len, rc4_key *key)
{
     unsigned char swapByte;
     unsigned char index1;
     unsigned char index2;
     unsigned char* state;
     short counter;

     state = &key->state[0];
     for(counter = 0; counter < 256; counter++)
     state[counter] = counter;
     key->x = 0;
     key->y = 0;
     index1 = 0;
     index2 = 0;
     for(counter = 0; counter < 256; counter++)
     {
          index2 = (key_data_ptr[index1] + state[counter] + index2) % 256;
          swap_byte(&state[counter], &state[index2]);

          index1 = (index1 + 1) % key_data_len;
     }
 }

 void rc4(unsigned char *buffer_ptr, int buffer_len, rc4_key *key) {
     unsigned char x;
     unsigned char y;
     unsigned char* state;
     unsigned char xorIndex;
     short counter;

     x = key->x;
     y = key->y;

     state = &key->state[0];
     for(counter = 0; counter < buffer_len; counter ++)
     {
          x = (x + 1) % 256;
          y = (state[x] + y) % 256;
          swap_byte(&state[x], &state[y]);

          xorIndex = state[x] + (state[y]) % 256;


          buffer_ptr[counter] ^= state[xorIndex];
      }
      key->x = x;
      key->y = y;
 }

