/*
cl_steam.c - steam(tm) broker implementation
Copyright (C) 2026 Xash3D FWGS contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#include <inttypes.h>
#include "common.h"
#include "client.h"
#include "net_ws.h"
#include "net_ws_private.h"

// What is a broker?
// From Wikipedia, the free encyclopedia:
// "The broker pattern is an architecture pattern that involves the use of an
// intermediary software entity, called a "broker", to facilitate communication
// between two or more software components. The broker acts as a "middleman"
// between the components, allowing them to communicate without being aware of
// each other's existence.
//
// Due to proprietary nature of Steamworks SDK, it cannot be run on same amount
// of platforms supported by Xash3D FWGS, neither we can link directly due to
// GNU GPLv3 license. However, here comes the broker, by running it (in trusted
// network, preferrably) on a machine that has Steam client installed, the
// engine can communicate with it, acquiring needed information to log-in into
// Steam protected multiplayer servers.

// Protocol constants
#define SBRK_FRAME_HEADER			"SBRK"
#define SBRK_FRAME_HEADER_SIZE		(sizeof(SBRK_FRAME_HEADER) - 1)
#define SBRK_FRAME_LENGTH_SIZE		2
#define SBRK_RESPONSE_HEADER		"sb_connect\n"
#define SBRK_RESPONSE_HEADER_SIZE	(sizeof(SBRK_RESPONSE_HEADER) - 1)
#define SBRK_MAX_FRAME_SIZE			4096
#define SBRK_CONNECT_TIMEOUT		10.0
#define SBRK_CONNECT_RETRY_DELAY	5.0
#define SBRK_TICKET_SIZE_MAX 		2048

#define SBRK_PLAYER_REQUEST_FMT			"sb_get_player %" PRIu64
#define SBRK_PLAYER_RESPONSE_HEADER		"sb_playerx\n"
#define SBRK_PLAYER_RESPONSE_HEADER_SIZE	(sizeof(SBRK_PLAYER_RESPONSE_HEADER) - 1)

#define SBRK_PLAYER_NAME_SIZE			128

// A single avatar field can never exceed the max payload of the frame that
// carries it, so this is a safe upper bound for the raw PNG buffer.
#define SBRK_AVATAR_PNG_MAX			SBRK_MAX_FRAME_SIZE

#define SBRK_PLAYER_POLL_INTERVAL		0.1
#define SBRK_PLAYER_CACHE_SIZE			32

#define SBRK_PLAYER_FIELD_NAME			(1u << 0)
#define SBRK_PLAYER_FIELD_AVATAR_SMALL	(1u << 1)
#define SBRK_PLAYER_FIELD_AVATAR_MEDIUM	(1u << 2)	// reserved, not sent by broker yet
#define SBRK_PLAYER_FIELD_AVATAR_LARGE	(1u << 3)	// reserved, not sent by broker yet
#define SBRK_PLAYER_FIELD_RELATIONSHIP	(1u << 4)
#define SBRK_PLAYER_FIELD_COUNTRY		(1u << 5)	// reserved, not sent by broker yet
#define SBRK_PLAYER_FIELD_GAME			(1u << 6)
#define SBRK_PLAYER_FIELD_RICH_PRESENCE	(1u << 7)	// reserved, not sent by broker yet
#define SBRK_PLAYER_FIELD_PERSONA_STATE	(1u << 8)

typedef enum
{
	SBRK_PLAYER_FIELD_TYPE_NAME 			= 1,
	SBRK_PLAYER_FIELD_TYPE_AVATAR_SMALL 	= 2,
	SBRK_PLAYER_FIELD_TYPE_AVATAR_MEDIUM 	= 3, // reserved
	SBRK_PLAYER_FIELD_TYPE_AVATAR_LARGE 	= 4, // reserved
	SBRK_PLAYER_FIELD_TYPE_RELATIONSHIP 	= 5,
	SBRK_PLAYER_FIELD_TYPE_COUNTRY 			= 6, // reserved
	SBRK_PLAYER_FIELD_TYPE_GAME 			= 7,
	SBRK_PLAYER_FIELD_TYPE_RICH_PRESENCE 	= 8, // reserved
	SBRK_PLAYER_FIELD_TYPE_PERSONA_STATE 	= 9
} sbrk_player_field_t;

typedef enum
{
	SBRK_PLAYER_RELATIONSHIP_NONE                  = 0,
	SBRK_PLAYER_RELATIONSHIP_FRIEND                = 1,
	SBRK_PLAYER_RELATIONSHIP_BLOCKED               = 2,
	SBRK_PLAYER_RELATIONSHIP_FRIENDSHIP_REQUESTED  = 3,
	SBRK_PLAYER_RELATIONSHIP_REQUESTING_FRIENDSHIP = 4,
} sbrk_player_relationship_t;

static CVAR_DEFINE_AUTO( cl_steam_broker_addr, "127.0.0.1:27420", FCVAR_PRIVILEGED|FCVAR_ARCHIVE, "address of steam broker instance" );

typedef enum
{
	SBRK_STATE_IDLE,
	SBRK_STATE_CONNECTING,
	SBRK_STATE_CONNECTED,
	SBRK_STATE_GAMESHUTDOWN
} sbrk_state_t;

typedef struct
{
	netadr_t adr;
	int socket;
	sbrk_state_t state;
	int challenge;
	netadr_t serveradr;
	double connection_timeout;
	double idle_cycle_timeout;
	uint8_t rx_buffer[SBRK_MAX_FRAME_SIZE + 64];
	uint8_t tx_buffer[SBRK_MAX_FRAME_SIZE + 64];
	uint32_t rx_buffer_pos;
	uint32_t tx_buffer_pos;
} steam_broker_t;

static steam_broker_t broker;
static sbrk_player_info_t g_sbrk_player_cache[SBRK_PLAYER_CACHE_SIZE];

static void SteamBroker_SetState( sbrk_state_t new_state )
{
	if( broker.state != new_state )
	{
		// we also may logging transitions if needed
		broker.state = new_state;
	}
}

static qboolean SteamBroker_UpdateBrokerAddress( void )
{
	if( NET_NetadrType( &broker.adr ) == NA_UNDEFINED )
	{
		if( !NET_StringToAdr( cl_steam_broker_addr.string, &broker.adr ))
			return false;
	}
	return true;
}

static void SteamBroker_CloseSocket( void )
{
	if( NET_IsSocketValid( broker.socket ))
	{
		closesocket( broker.socket );
		broker.socket = INVALID_SOCKET;
	}
	broker.rx_buffer_pos = 0;
	broker.tx_buffer_pos = 0;
}

static void SteamBroker_Disconnect( void )
{
	SteamBroker_CloseSocket();
	SteamBroker_SetState( SBRK_STATE_IDLE );
}

static qboolean SteamBroker_ConnectImpl( void )
{
	int addr_family;
	struct sockaddr_storage addr = { 0 };

	if( NET_NetadrType( &broker.adr ) == NA_IP )
	{
		addr_family = AF_INET;
	}
	else if( NET_NetadrType( &broker.adr ) == NA_IP6 )
	{
		addr_family = AF_INET6;
	}
	else
	{
		Con_Printf( S_ERROR "%s: unsupported broker address type for %s\n", __func__, cl_steam_broker_addr.string );
		return false;
	}

	broker.socket = socket( addr_family, SOCK_STREAM, IPPROTO_TCP );
	if( !NET_IsSocketValid( broker.socket ))
	{
		Con_Printf( S_ERROR "%s: failed to create socket\n", __func__ );
		return false;
	}

	if( !NET_MakeSocketNonBlocking( broker.socket ))
	{
		Con_Printf( S_ERROR "%s: failed to set non-blocking mode, error %s\n", __func__, NET_ErrorString( ));
		SteamBroker_CloseSocket();
		return false;
	}

	NET_NetadrToSockadr( &broker.adr, &addr );

	int result = connect( broker.socket, (struct sockaddr *)&addr, NET_SockAddrLen( &addr ));
	if( NET_IsSocketError( result ))
	{
		int err = WSAGetLastError();
		if( err != WSAEWOULDBLOCK && err != WSAEALREADY && err != WSAEINPROGRESS )
		{
			Con_Printf( S_ERROR "%s: failed to connect to broker at %s with error %s\n", __func__, cl_steam_broker_addr.string, NET_ErrorString( ));
			SteamBroker_CloseSocket();
			return false;
		}
	}

	broker.connection_timeout = Platform_DoubleTime() + SBRK_CONNECT_TIMEOUT;
	SteamBroker_SetState( SBRK_STATE_CONNECTING );
	return true;
}

static qboolean SteamBroker_SendFrame( const char *payload, size_t payload_size )
{
	if( payload_size > SBRK_MAX_FRAME_SIZE )
	{
		Con_Printf( S_WARN "%s: payload too large (%zu > %u)\n", __func__, payload_size, SBRK_MAX_FRAME_SIZE );
		return false;
	}

	uint8_t frame[SBRK_MAX_FRAME_SIZE + 6];
	sizebuf_t sb;

	MSG_Init( &sb, "SteamBroker_SendFrame", frame, sizeof( frame ));

	MSG_WriteBytes( &sb, SBRK_FRAME_HEADER, SBRK_FRAME_HEADER_SIZE );
	MSG_WriteShort( &sb, payload_size );
	MSG_WriteBytes( &sb, payload, payload_size );

	size_t frame_size = MSG_GetRealBytesWritten( &sb );
	int sent = send( broker.socket, (const char *)frame, frame_size, 0 );
	if( NET_IsSocketError( sent ))
	{
		int err = WSAGetLastError();
		if( err != WSAEWOULDBLOCK && err != WSAEALREADY )
		{
			Con_Printf( S_ERROR "%s: send error %s\n", __func__, NET_ErrorString( ));
			SteamBroker_Disconnect( );
			return false;
		}
		sent = 0;
	}

	// bufferize unsent data for deferred sending
	size_t unsent = frame_size - sent;
	if( unsent > 0 )
	{
		size_t available = sizeof( broker.tx_buffer ) - broker.tx_buffer_pos;
		if( available < unsent )
		{
			Con_Printf( S_ERROR "%s: transmit buffer overflow (%zu > %zu)\n", __func__, unsent, available );
			SteamBroker_Disconnect( );
			return false;
		}

		memcpy( broker.tx_buffer + broker.tx_buffer_pos, frame + sent, unsent );
		broker.tx_buffer_pos += unsent;
	}

	return true;
}

static void SteamBroker_SendPlayerInfoRequest( uint64_t steamid )
{
	char buf[64];
	int len = Q_snprintf( buf, sizeof( buf ), SBRK_PLAYER_REQUEST_FMT, steamid );

	if( len > 0 )
		SteamBroker_SendFrame( buf, len );
}

static sbrk_player_info_t *SteamBroker_FindPlayerSlot( uint64_t steamid )
{
	int i;

	for( i = 0; i < SBRK_PLAYER_CACHE_SIZE; i++ )
	{
		if( g_sbrk_player_cache[i].steamid == steamid )
			return &g_sbrk_player_cache[i];
	}

	return NULL;
}

// Precondition: caller has already verified no slot for `steamid` exists.
// Picks a free slot if available, otherwise evicts the least-recently-
// updated non-pending slot (LRU by request_time).
static sbrk_player_info_t *SteamBroker_AllocatePlayerSlot( uint64_t steamid )
{
	sbrk_player_info_t *free_slot = NULL;
	sbrk_player_info_t *oldest_slot = NULL;
	sbrk_player_info_t *target;
	double oldest_time = 0.0;
	int i;

	for( i = 0; i < SBRK_PLAYER_CACHE_SIZE; i++ )
	{
		sbrk_player_info_t *slot = &g_sbrk_player_cache[i];

		if( !free_slot && slot->status == SBRK_PLAYER_UNREQUESTED )
			free_slot = slot;

		if( slot->status != SBRK_PLAYER_PENDING &&
			( !oldest_slot || slot->request_time < oldest_time ))
		{
			oldest_slot = slot;
			oldest_time = slot->request_time;
		}
	}

	target = free_slot ? free_slot : oldest_slot;
	if( !target )
		return NULL; // cache full of in-flight requests, nothing evictable

	memset( target, 0, sizeof( *target ));
	target->steamid = steamid;
	target->status = SBRK_PLAYER_PENDING;
	target->request_time = Platform_DoubleTime();

	return target;
}

int SteamBroker_GetPlayerInfo( uint64_t steamid, sbrk_player_info_t *out )
{
	sbrk_player_info_t *entry;

	if( broker.state != SBRK_STATE_CONNECTED )
		return SBRK_PLAYER_UNAVAILABLE;

	if( steamid == 0 )
		return SBRK_PLAYER_UNAVAILABLE; // 0 collides with the zero-initialized "free slot" marker

	entry = SteamBroker_FindPlayerSlot( steamid );

	if( !entry )
	{
		entry = SteamBroker_AllocatePlayerSlot( steamid );
		if( !entry )
			return SBRK_PLAYER_PENDING; // couldn't even start tracking it yet

		SteamBroker_SendPlayerInfoRequest( steamid );
		return SBRK_PLAYER_PENDING;
	}

	switch( entry->status )
	{
	case SBRK_PLAYER_READY:
		if( out )
			*out = *entry;
		return SBRK_PLAYER_READY;

	case SBRK_PLAYER_UNAVAILABLE:
		return SBRK_PLAYER_UNAVAILABLE;

	case SBRK_PLAYER_PENDING:
		if( Platform_DoubleTime() - entry->request_time >= SBRK_PLAYER_POLL_INTERVAL )
		{
			SteamBroker_SendPlayerInfoRequest( steamid );
			entry->request_time = Platform_DoubleTime();
		}
		return SBRK_PLAYER_PENDING;

	case SBRK_PLAYER_UNREQUESTED:
	default:
		// Shouldn't happen in practice now that steamid==0 is rejected above,
		// but handle defensively instead of falling through with no return.
		entry->steamid = steamid;
		entry->status = SBRK_PLAYER_PENDING;
		entry->request_time = Platform_DoubleTime();
		SteamBroker_SendPlayerInfoRequest( steamid );
		return SBRK_PLAYER_PENDING;
	}
}

// Parses an "sb_playerx" payload into the matching cache slot. `sb` must
// already be positioned right after the common frame + response header
// (SteamBroker_ProcessFrame consumes those bytes before dispatching here) —
// this function does NOT re-read any header of its own.
static void SteamBroker_ProcessPlayerResponse( sizebuf_t *sb )
{
	sbrk_player_info_t *player;
	uint64_t steamid;

	if( MSG_GetNumBytesLeft( sb ) < sizeof( uint64_t ) + sizeof( uint32_t ))
		return;

	MSG_ReadBytes( sb, &steamid, sizeof( steamid ), sizeof( steamid ));
	MSG_ReadDword( sb ); // field flags: informational only, each field is self-delimited below

	player = SteamBroker_FindPlayerSlot( steamid );

	if( !player )
	{
		Con_Printf( S_WARN "%s: response for unknown SteamID %"PRIu64"\n", __func__, steamid );
		return;
	}

	player->name[0] = '\0';
	player->relationship = SBRK_PLAYER_RELATIONSHIP_NONE;
	player->persona_state = 0;
	player->game_app_id = 0;
	// Note: avatar_png/avatar_png_size are intentionally NOT reset here.
	// The broker only attaches the avatar field once it has finished
	// fetching it from Steam, which may be a response or two after this
	// one; resetting unconditionally would throw away an avatar we
	// already received while we wait for nothing to change.

	// Generic TLV walk: every field is `type(1) + length(4, LE) + data(length)`,
	// with NO exceptions for fixed-size fields like relationship or persona
	// state. Always consuming the length prefix (and using it to skip
	// unknown or partially-understood fields) keeps the stream in sync even
	// if a future broker adds field types this client doesn't know about yet.
	while( MSG_GetNumBytesLeft( sb ) > 0 )
	{
		byte type;
		uint32_t field_len;

		if( MSG_GetNumBytesLeft( sb ) < 1 )
			break;

		type = MSG_ReadByte( sb );

		if( MSG_GetNumBytesLeft( sb ) < sizeof( uint32_t ))
			return;

		field_len = MSG_ReadDword( sb );

		if( MSG_GetNumBytesLeft( sb ) < field_len )
			break;

		switch( type )
		{
		case SBRK_PLAYER_FIELD_TYPE_NAME:
			if( field_len >= sizeof( player->name ))
			{
				Con_Printf( S_WARN "%s: player name too long (%u)\n", __func__, field_len );
				MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
				break;
			}

			MSG_ReadBytes( sb, player->name, sizeof( player->name ), field_len );
			player->name[field_len] = '\0';
			break;

		case SBRK_PLAYER_FIELD_TYPE_AVATAR_SMALL:
			if( field_len > sizeof( player->avatar_png ))
			{
				Con_Printf( S_WARN "%s: avatar payload too large (%u)\n", __func__, field_len );
				MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
				break;
			}

			MSG_ReadBytes( sb, player->avatar_png, sizeof( player->avatar_png ), field_len );
			player->avatar_png_size = field_len;
			player->avatar_dirty = true;
			break;

		case SBRK_PLAYER_FIELD_TYPE_AVATAR_MEDIUM:
		case SBRK_PLAYER_FIELD_TYPE_AVATAR_LARGE:
			// reserved
			MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
			break;

		case SBRK_PLAYER_FIELD_TYPE_RELATIONSHIP:
			if( field_len < 1 )
			{
				MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
				break;
			}

			player->relationship = MSG_ReadByte( sb );
			if( field_len > 1 )
				MSG_SeekToBit( sb, ( field_len - 1 ) << 3, SEEK_CUR );
			break;

		case SBRK_PLAYER_FIELD_TYPE_COUNTRY:
			// Reserved: broker doesn't send this field yet. Skipped via the
			// length prefix rather than parsed, so it stays wire-compatible
			// whenever it does get populated.
			MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
			break;

		case SBRK_PLAYER_FIELD_TYPE_GAME:
			if( field_len < sizeof( uint32_t ))
			{
				MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
				break;
			}

			player->game_app_id = MSG_ReadDword( sb );
			if( field_len > sizeof( uint32_t ))
				MSG_SeekToBit( sb, ( field_len - sizeof( uint32_t )) << 3, SEEK_CUR );
			break;

		case SBRK_PLAYER_FIELD_TYPE_RICH_PRESENCE:
			// Reserved: same as country above.
			MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
			break;

		case SBRK_PLAYER_FIELD_TYPE_PERSONA_STATE:
			if( field_len < 1 )
			{
				MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
				break;
			}

			player->persona_state = MSG_ReadByte( sb );
			if( field_len > 1 )
				MSG_SeekToBit( sb, ( field_len - 1 ) << 3, SEEK_CUR );
			break;

		default:
			// Unknown field type: skip exactly `field_len` bytes instead of
			// bailing out, so one field neither of us recognizes yet doesn't
			// desync the rest of the payload.
			Con_Printf( S_WARN "%s: unknown player field type %u, skipping %u bytes\n", __func__, type, field_len );
			MSG_SeekToBit( sb, field_len << 3, SEEK_CUR );
			break;
		}
	}

	player->status = SBRK_PLAYER_READY;
	player->request_time = Platform_DoubleTime();

	Con_DPrintf( "%s: received player %"PRIu64" \"\n",
		__func__, player->steamid );
}

static qboolean SteamBroker_ProcessFrame( void )
{
	if( broker.rx_buffer_pos < SBRK_FRAME_HEADER_SIZE + SBRK_FRAME_LENGTH_SIZE )
		return false;

	sizebuf_t sb;
	MSG_Init( &sb, "SteamBroker_ProcessFrame", broker.rx_buffer, broker.rx_buffer_pos );

	// verify frame header
	char header[SBRK_FRAME_HEADER_SIZE];
	if( !MSG_ReadBytes( &sb, header, sizeof( header ), SBRK_FRAME_HEADER_SIZE ))
		return false;

	if( memcmp( header, SBRK_FRAME_HEADER, SBRK_FRAME_HEADER_SIZE ) != 0 )
	{
		Con_Printf( S_ERROR "%s: invalid frame header\n", __func__ );
		SteamBroker_Disconnect( );
		return false;
	}

	uint16_t payload_size = MSG_ReadShort( &sb );
	uint32_t frame_size = SBRK_FRAME_HEADER_SIZE + SBRK_FRAME_LENGTH_SIZE + payload_size;

	if( MSG_GetNumBytesLeft( &sb ) < payload_size )
		return false; // need more data

	char response_header[SBRK_RESPONSE_HEADER_SIZE];

	if( !MSG_ReadBytes( &sb, response_header, sizeof( response_header ), SBRK_RESPONSE_HEADER_SIZE ))
		return false;

	if( memcmp( response_header, SBRK_RESPONSE_HEADER, SBRK_RESPONSE_HEADER_SIZE ) == 0 )
	{
		// sb_connect response

		int32_t challenge = MSG_ReadLong( &sb );

		if( broker.challenge != challenge )
		{
			Con_Printf( S_ERROR "%s: challenge mismatch\n", __func__ );
		}
		else
		{
			uint64_t steam_id;
			MSG_ReadBytes( &sb, &steam_id, sizeof( steam_id ), sizeof( steam_id ));
			uint32_t ticket_size = MSG_ReadDword( &sb );
			uint8_t ticket_data[SBRK_TICKET_SIZE_MAX];

			if( ticket_size > SBRK_TICKET_SIZE_MAX )
			{
				Con_Printf( S_ERROR "%s: ticket size exceeds limit (%u)\n", __func__, ticket_size );
			}
			else if( MSG_ReadBytes( &sb, ticket_data, sizeof( ticket_data ), ticket_size ))
			{
					Con_Printf( "%s: SteamID: %"PRIu64", ticket: [%d, %d, %d, %d...]\n", __func__, steam_id, ticket_data[0], ticket_data[1], ticket_data[2], ticket_data[3] );

				memcpy( cls.steamid, &steam_id, sizeof( cls.steamid ));
				CL_SendGoldSrcConnectPacket( broker.serveradr, broker.challenge, ticket_data, ticket_size );
				cls.broker_wait = false;
			}
			else
			{
				Con_Printf( S_ERROR "%s: failed to read ticket data\n", __func__ );
			}
		}
	}
	else if( memcmp( response_header, SBRK_PLAYER_RESPONSE_HEADER, SBRK_PLAYER_RESPONSE_HEADER_SIZE ) == 0 )
	{
		// sb_playerx response — `sb` is already positioned right after the
		// header we just verified above, so hand it off as-is.
		SteamBroker_ProcessPlayerResponse( &sb );
	}
	else
	{
		Con_Printf( S_ERROR "%s: unknown response header\n", __func__ );
	}

	// remove processed frame from buffer
	memmove( broker.rx_buffer, broker.rx_buffer + frame_size, broker.rx_buffer_pos - frame_size );
	broker.rx_buffer_pos -= frame_size;

	return true;
}

static void SteamBroker_HandleDataTx( void )
{
	if( broker.tx_buffer_pos == 0 )
		return;

	int sent = send( broker.socket, (const char *)broker.tx_buffer, broker.tx_buffer_pos, 0 );
	if( NET_IsSocketError( sent ))
	{
		int err = WSAGetLastError();
		if( err != WSAEWOULDBLOCK && err != WSAEALREADY )
		{
			Con_Printf( S_ERROR "%s: send error %s\n", __func__, NET_ErrorString( ));
			SteamBroker_Disconnect( );
		}
		return;
	}

	if( sent > 0 )
	{
		// remove sent data from buffer
		memmove( broker.tx_buffer, broker.tx_buffer + sent, broker.tx_buffer_pos - sent );
		broker.tx_buffer_pos -= sent;
	}
}

static void SteamBroker_HandleDataRx( void )
{
	int available = sizeof( broker.rx_buffer ) - broker.rx_buffer_pos;
	if( available <= 0 )
	{
		Con_Printf( S_ERROR "%s: receive buffer overflow\n", __func__ );
		SteamBroker_Disconnect( );
		return;
	}

	int received = recv( broker.socket, (char *)broker.rx_buffer + broker.rx_buffer_pos, available, 0 );
	if( NET_IsSocketError( received ))
	{
		int err = WSAGetLastError();
		if( err != WSAEWOULDBLOCK && err != WSAEALREADY )
		{
			Con_Printf( S_ERROR "%s: recv error %s\n", __func__, NET_ErrorString( ));
			SteamBroker_Disconnect( );
		}
		return;
	}

	if( received == 0 )
	{
		Con_Printf( S_NOTE "%s: connection closed by broker\n", __func__ );
		SteamBroker_Disconnect( );
		return;
	}

	broker.rx_buffer_pos += received;

	while( SteamBroker_ProcessFrame( ));
}

static void SteamBroker_UpdateIdle( void )
{
	if( broker.idle_cycle_timeout < Platform_DoubleTime( ))
	{
		if( SteamBroker_UpdateBrokerAddress( ))
		{
			SteamBroker_ConnectImpl( );
		}
		else
		{
			Con_Printf( S_ERROR "%s: failed to resolve broker address \"%s\"\n", __func__, cl_steam_broker_addr.string );
		}
		broker.idle_cycle_timeout = Platform_DoubleTime() + SBRK_CONNECT_RETRY_DELAY;
	}
}

static void SteamBroker_AnnounceGameStart( const char *gamedir )
{
	if( Q_stricmp( cl_ticket_generator.string, "steam" ) != 0 )
		return;

	if( broker.state != SBRK_STATE_CONNECTED )
		return;

	// sb_gamedir <gamedir>
	char buf[512];
	int len = Q_snprintf( buf, sizeof( buf ), "sb_gamedir %s", gamedir );

	if( len > 0 )
		SteamBroker_SendFrame( buf, len );
}

static void SteamBroker_AnnounceGameShutdown( void )
{
	if( Q_stricmp( cl_ticket_generator.string, "steam" ) != 0 )
		return;

	if( broker.state != SBRK_STATE_CONNECTED )
		return;

	SteamBroker_SendFrame( "sb_terminate", sizeof( "sb_terminate" ) - 1 );
}

static void SteamBroker_UpdateConnecting( void )
{
	if( Platform_DoubleTime() > broker.connection_timeout )
	{
		Con_Printf( S_WARN "%s: connection to %s timed out\n", __func__, cl_steam_broker_addr.string );
		SteamBroker_Disconnect();
		return;
	}

	fd_set writefds;
	FD_ZERO( &writefds );
	FD_SET( broker.socket, &writefds );

	struct timeval tv = { 0 };

#if XASH_WIN32
	int select_result = select( 0, NULL, &writefds, NULL, &tv );
#else
	int select_result = select( broker.socket + 1, NULL, &writefds, NULL, &tv );
#endif
	if( select_result == SOCKET_ERROR )
	{
		Con_Printf( S_ERROR "%s: select() failed\n", __func__ );
		SteamBroker_Disconnect();
		return;
	}

	if( FD_ISSET( broker.socket, &writefds ))
	{
		// socket is writable - connection established or failed
		int err = 0;
		socklen_t err_len = sizeof( err );
		if( NET_IsSocketError( getsockopt( broker.socket, SOL_SOCKET, SO_ERROR, (char *)&err, &err_len )))
		{
			Con_Printf( S_ERROR "%s: getsockopt() failed\n", __func__ );
			SteamBroker_Disconnect();
			return;
		}
		else if( err != 0 )
		{
			Con_Printf( S_ERROR "%s: connection failed with error %d\n", __func__, err );
			SteamBroker_Disconnect();
			return;
		}
		else
		{
			broker.connection_timeout = 0;
			Con_Printf( S_NOTE "%s: connected to broker at %s\n", __func__, cl_steam_broker_addr.string );
			SteamBroker_SetState( SBRK_STATE_CONNECTED );
			SteamBroker_AnnounceGameStart( GI->gamefolder );
		}
	}
}

static void SteamBroker_UpdateConnected( void )
{
	SteamBroker_HandleDataTx( );
	SteamBroker_HandleDataRx( );
}

qboolean SteamBroker_InitiateGameConnection( netadr_t serveradr, int challenge )
{
	// only ipv4 supported
	if( NET_NetadrType( &serveradr ) != NA_IP )
		return false;

	if( broker.state != SBRK_STATE_CONNECTED )
	{
		Con_Printf( S_WARN "%s: broker not connected\n", __func__ );
		return false;
	}

	broker.challenge = challenge;
	broker.serveradr = serveradr;

	// sb_connect <ip:port> <server_steamid> <secure> <challenge>
	char buf[512];
	int len = Q_snprintf( buf, sizeof( buf ), "sb_connect %s %"PRIu64" %d %d", NET_AdrToString( serveradr ), cls.server_steamid, cls.vac2_secure ? 1 : 0, challenge );

	if( !SteamBroker_SendFrame( buf, len ))
		return false;

	return true;
}

void SteamBroker_TerminateGameConnection( void )
{
	if( broker.state != SBRK_STATE_CONNECTED )
		return;

	if( Q_stricmp( cl_ticket_generator.string, "steam" ) != 0 )
		return;

	// sb_disconnect <ip:port> <challenge>
	char buf[512];
	int len = Q_snprintf( buf, sizeof( buf ), "sb_disconnect %s %d", NET_AdrToString( cls.serveradr ), broker.challenge );

	SteamBroker_SendFrame( buf, len );
}

void SteamBroker_Frame( void )
{
	if( FBitSet( cl_steam_broker_addr.flags | cl_ticket_generator.flags, FCVAR_CHANGED ))
	{
		ClearBits( cl_ticket_generator.flags, FCVAR_CHANGED );
		ClearBits( cl_steam_broker_addr.flags, FCVAR_CHANGED );

		if( broker.state != SBRK_STATE_IDLE )
		{
			SteamBroker_Disconnect();
		}

		// reinitialize address
		NET_NetadrSetType( &broker.adr, NA_UNDEFINED );
	}

	if( Q_stricmp( cl_ticket_generator.string, "steam" ) != 0 )
		return;

	// update state machine
	switch( broker.state )
	{
	case SBRK_STATE_IDLE:
		SteamBroker_UpdateIdle( );
		break;
	case SBRK_STATE_CONNECTING:
		SteamBroker_UpdateConnecting( );
		break;
	case SBRK_STATE_CONNECTED:
		SteamBroker_UpdateConnected( );
		break;
	case SBRK_STATE_GAMESHUTDOWN:
		// do nothing, just wait for game shutdown
		break;
	}
}

void SteamBroker_Init( void )
{
	broker.state = SBRK_STATE_IDLE;
	broker.socket = INVALID_SOCKET;
	broker.rx_buffer_pos = 0;
	broker.tx_buffer_pos = 0;
	memset( g_sbrk_player_cache, 0, sizeof( g_sbrk_player_cache ));
	Cvar_RegisterVariable( &cl_steam_broker_addr );
	NET_NetadrSetType( &broker.adr, NA_UNDEFINED );
}

void SteamBroker_Shutdown( void )
{
	if( Q_stricmp( cl_ticket_generator.string, "steam" ) != 0 )
		return;

	SteamBroker_AnnounceGameShutdown( );
	SteamBroker_SetState( SBRK_STATE_GAMESHUTDOWN );
}
