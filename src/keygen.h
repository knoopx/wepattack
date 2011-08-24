/********************************************************************************
* File:   		keygen.c
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

#ifndef WEPATTACK_KEYGEN_H
#define WEPATTACK_KEYGEN_H

void wep_keygen128(const char *str, u_char *keys);

void wep_keygen40(const char *str, u_char *keys);

void wep_keyprint(u_char *keys);

#endif
