/***
*
*	Copyright (c) 1996-2002, Valve LLC. All rights reserved.
*
*	This product contains software technology licensed from Id
*	Software, Inc. ("Id Technology").  Id Technology (c) 1996 Id Software, Inc.
*	All Rights Reserved.
*
*   Use, distribution, and modification of this source code and/or resulting
*   object code is restricted to non-commercial enhancements to products from
*   Valve LLC.  All other use, distribution, or modification is prohibited
*   without written permission from Valve LLC.
*
****/

#ifndef CUSTOM_H
#define CUSTOM_H

#include "const.h"

/////////////////
// Customization
// passed to pfnPlayerCustomization
// For automatic downloading.

// WAD3 structures for spray and texture parsing
#define WAD3_SPRAY_TYPE  0x40
#define WAD3_MIPTEX_TYPE 0x43

typedef struct
{
	char identification[4]; // "WAD3"
	int  numlumps;
	int  infotableofs;
} wad3header_t;

typedef struct
{
	int  filepos;
	int  disksize;
	int  size; // uncompressed
	char type;
	char compression;
	char pad1, pad2;
	char name[16];
} wad3lump_t;

typedef struct
{
	char     texture_name[16];
	uint32_t width;
	uint32_t height;
	uint32_t mip_offsets[4];
	// ... mipmaps follow ...
	// ... then short colors_used, then palette ...
} miptex_t;

typedef enum
{
	t_sound = 0,
	t_skin,
	t_model,
	t_decal,
	t_generic,
	t_eventscript,
	t_world,			// Fake type for world, is really t_model
} resourcetype_t;

typedef struct
{
	int		size;
} _resourceinfo_t;

typedef struct resourceinfo_s
{
	_resourceinfo_t	info[8];
} resourceinfo_t;

#define RES_FATALIFMISSING	(1<<0)	// Disconnect if we can't get this file.
#define RES_WASMISSING	(1<<1)	// Do we have the file locally, did we get it ok?
#define RES_CUSTOM		(1<<2)	// Is this resource one that corresponds to another player's customization
				// or is it a server startup resource.
#define RES_REQUESTED	(1<<3)	// Already requested a download of this one
#define RES_PRECACHED	(1<<4)	// Already precached
#define RES_ALWAYS		(1<<5)	// Download always even if available on client
#define RES_CHECKFILE	(1<<7)	// Check file on client

// this archive was already mounted after rescan
// only makes sense for archives and on client
#define RES_EXTRA_ARCHIVE_CHECKED BIT( 0 )

typedef struct resource_s
{
	char			szFileName[64];	// File name to download/precache.
	resourcetype_t		type;		// t_sound, t_skin, t_model, t_decal.
	int			nIndex;		// For t_decals
	int			nDownloadSize;	// Size in Bytes if this must be downloaded.
	unsigned char		ucFlags;

	// for handling client to client resource propagation
	unsigned char		rgucMD5_hash[16];	// To determine if we already have it.
	unsigned char		playernum;	// Which player index this resource is associated with,
						// if it's a custom resource.

	unsigned char		rguc_reserved[32];	// For future expansion
	unsigned short		ucExtraFlags; // fwgs extension, doesn't change the size of struct because of compiler padding
	struct resource_s		*pNext;		// Next in chain.
	struct resource_s		*pPrev;
} resource_t;

typedef struct customization_s
{
	qboolean			bInUse;		// Is this customization in use;
	resource_t		resource;		// The resource_t for this customization
	qboolean			bTranslated;	// Has the raw data been translated into a useable format?
						// (e.g., raw decal .wad make into texture_t *)
	int			nUserData1;	// Customization specific data
	int			nUserData2;	// Customization specific data
	void			*pInfo;		// Buffer that holds the data structure that references
						// the data (e.g., the cachewad_t)
	void			*pBuffer;		// Buffer that holds the data for the customization
						// (the raw .wad data)
	struct customization_s	*pNext;		// Next in chain
} customization_t;

#define FCUST_FROMHPAK		( 1<<0 )
#define FCUST_WIPEDATA		( 1<<1 )
#define FCUST_IGNOREINIT		( 1<<2 )

STATIC_CHECK_SIZEOF( customization_t, 164, 192 );
STATIC_CHECK_SIZEOF( resource_t, 136, 144 );

#endif // CUSTOM_H
