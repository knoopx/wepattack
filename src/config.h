/*******************************************************************************
* File:   		config.h
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Configuration and constants
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
******************************************************************************/

#ifndef WEPATTACK_CONFIG_H
#define WEPATTACK_CONFIG_H


#define LOGFILE_PREFIX		"WepAttack"
#define LOGFILE_POSTFIX		".log"

#define PACKET_LENGTH 		2428
#define HEADER_LENGTH 		28

#define MODE_WEP 		0x20
#define MODE_KEYGEN 		0x40

#define WEPKEYSIZE      	5
#define WEPSTRONGKEYSIZE	13
#define WEPKEYS         	4
#define WEPKEYSTORE     	(WEPKEYSIZE * WEPKEYS)

#define DEBUG 			0
#define VERSION			"0.1.3"


#endif
