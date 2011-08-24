/**********************************************************************
* File:   		nwepgen.h
* Date:   		2002-09-24
* Author: 		Alain Girardet/Dominik Blunk
* Last Modified:	2002-10-24
*
* Description: Management function for generating wep keys, used
* on most access points
*
**********************************************************************/

#ifndef WEPATTACK_NWEPGEN_H
#define WEPATTACK_NWEPGEN_H

/*----------------------------------------------------------------
* nwepgen
*
* Generates a set of WEP keys from a generator string.  This is
* intended as a convenience.  Entering hex bytes can be a pain.
*
* Based on an algorithm supplied by Neesus Datacom,
* http://www.neesus.com
*
* This function was authored by Zoom Telephonics Engineer
* Juan Arango.
* http://www.zoomtel.com
*
* Juan's Note:
* Changing the code in this function could make this product
* incompatible with other ZoomAir wireless products because
* these other products rely on Microsoft's rand() and srand()
* function implementations!!!  This code uses the same algorithm.
*
* Distributed with permission from Zoom Telephonics.
*
* Arguments:
* 	genstr		a null terminated string
*	keylen		number of bytes in key
* 	wep_key		a 2d array that is filled with the wep keys
* Returns:
*	nothing
----------------------------------------------------------------*/
void nwepgen(char *genstr, int keylen, UINT8 wep_key[WLAN_WEP_NKEYS][WLAN_WEP_MAXKEYLEN]);

#endif
