/********************************************************************************
* File:   		modes.c
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

#include <sys/types.h>
#include <stdio.h>
#include "modes.h"
#include "rc4.h"
#include "wlan/wlan_compat.h"
#include "wlan/p80211hdr.h"
#include "keygen.h"
#include "config.h"
#include "wepattack.h"
#include "wepfilter.h"
#include "verify.h"

static rc4_key 		gen_key;
static unsigned char 	decrypted_stream[2400];

//
// load key and iv and generates rc4 key
//
static rc4_key* generate_rc4_key(const unsigned char *key, const int key_length,
		 const unsigned char* iv) {

	int i;
	unsigned char secret[16];

	// load key
	for(i=0;i<key_length;i++) {
		secret[3+i] = key[i];
	}

	// load iv
	memcpy(secret, current_packet->frame.iv, 3);

	// generate rc4 key
	prepare_key(secret, key_length+3, &gen_key);

	return &gen_key;
}

//
// applies rc4 on data, decrypted data will be stored in decrypted stream
//
static void process_rc4_key(const unsigned char *data,
		const int decrypt_length, rc4_key *key) {

	int i;
	FILE *f;

	memcpy(decrypted_stream, data, decrypt_length);

	rc4(decrypted_stream, decrypt_length, key);

	if (DEBUG) {
		f = fopen("decrypt.txt", "wb");
		for(i=0;i<decrypt_length;i++) {
			fprintf(f,"%c",decrypted_stream[i]);
		}
		fclose(f);
	}
}

int mode_keygen(const unsigned char *key, int key_length, int generate_length) {

	int size, offset;
	rc4_key *rc4_key_gen;
	unsigned char iv[3];

	// array for keygen generated wep keys
	u_char wep_key[WEPKEYSTORE];

	// generate wep keys based on key with keygen
	if (generate_length == 5) {
		wep_keygen40(key, wep_key);
		offset = current_packet->frame.key * 5;
	}
	else {
		wep_keygen128(key, wep_key);
		offset = 0;
	}

	// generate rc4 key
	rc4_key_gen = generate_rc4_key((unsigned char*)(wep_key+offset),
		generate_length, current_packet->frame.iv);

	// process rc4 only on first byte of frame
	process_rc4_key(current_packet->frame.payload, 1 ,rc4_key_gen);

	// verify if snap header is equal then second verify crc32
	// the whole stream must be decrypted again because the crc is
	// located at the end of the stream
	if (verify_snap(decrypted_stream)) {

		rc4_key_gen = generate_rc4_key((unsigned char*)(wep_key+offset),
			generate_length, current_packet->frame.iv);

		size = current_packet->framesize-HEADER_LENGTH;

		// process rc4 on the whole frame
		process_rc4_key(current_packet->frame.payload,
			size ,rc4_key_gen);

		if(verify_crc32(decrypted_stream, size-4, (unsigned long*)
			(decrypted_stream+size-4))) {

			// save information to list if crc is ok
			memcpy(current_packet->secret, (unsigned char*)(wep_key+offset),
				generate_length);
			strcpy(current_packet->nwep_secret, key);
			current_packet->cracked = 1;
			current_packet->encryption = MODE_KEYGEN | generate_length;

			return 1;
		}
	}

	return 0;
}

int mode_wep(const unsigned char *key, int key_length, int generate_length) {

	int size, i;
	rc4_key *rc4_key_gen;
	unsigned char iv[3];
	unsigned char padded_key[20];

	memcpy(padded_key, key, key_length);

	// pad key with NULL if key is shorter than generate_length
	for(i=key_length;i<generate_length;i++) {
		padded_key[3+i] = 0;
	}

	// generate rc4 key
	rc4_key_gen = generate_rc4_key(padded_key,
		generate_length, current_packet->frame.iv);

	// process rc4 on first byte of stream
	process_rc4_key(current_packet->frame.payload, 1 ,rc4_key_gen);

	// verify if snap header is equal then second verify crc32
	// the whole stream must be decrypted again because the crc is
	// located at the end of the stream
	if (verify_snap(decrypted_stream)) {

		rc4_key_gen = generate_rc4_key(padded_key,
			generate_length, current_packet->frame.iv);

		size = current_packet->framesize-HEADER_LENGTH;

		// process rc4 on the whole frame
		process_rc4_key(current_packet->frame.payload,
			size, rc4_key_gen);

		if(verify_crc32(decrypted_stream, size-4, (unsigned long*)
			(decrypted_stream+size-4))) {

			// save information to list if crc is ok
			memcpy(current_packet->secret, padded_key, generate_length);
			current_packet->cracked = 1;
			current_packet->encryption = MODE_WEP | generate_length;

			return 1;
		}
	}

	return 0;
}

