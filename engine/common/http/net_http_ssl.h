/*
net_http_ssl.h - SSL/TLS wrapper for HTTP client
Copyright (C) 2026 Sergey Degtyar @pwd491

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
*/

#ifndef NET_HTTP_SSL_H
#define NET_HTTP_SSL_H

#include "common.h"

#ifdef XASH_HAVE_MBEDTLS
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
#include "psa/crypto.h"
#endif
#endif

/*
=================================================

Transport abstraction for HTTP/HTTPS

This abstraction allows the HTTP code to work
with both plain TCP sockets and SSL/TLS connections
transparently.

=================================================
*/

typedef struct http_transport_s
{
	int socket;              // TCP socket (always present)
	qboolean is_ssl;         // Is this an SSL connection?
	qboolean is_ssl_initialized; // Has mbedTLS context been initialized?
	qboolean is_ssl_established; // Has SSL handshake completed?
	
#ifdef XASH_HAVE_MBEDTLS
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;
	mbedtls_net_context net_ctx;  // Network context for mbedTLS BIO callbacks
	qboolean verify_required;    // Track if certificate verification is required
	// CA certificate is stored globally, not per-transport
#endif
	
	// Function pointers for read/write/close
	int (*read)( struct http_transport_s *transport, void *buf, size_t len );
	int (*write)( struct http_transport_s *transport, const void *buf, size_t len );
	void (*close)( struct http_transport_s *transport );
} http_transport_t;

/*
==============
HTTP_SSL_Init

Initialize SSL/TLS subsystem
==============
*/
qboolean HTTP_SSL_Init( void );

/*
==============
HTTP_SSL_Shutdown

Shutdown SSL/TLS subsystem
==============
*/
void HTTP_SSL_Shutdown( void );

/*
==============
HTTP_SSL_TransportInit

Initialize transport structure for plain HTTP
==============
*/
void HTTP_SSL_TransportInit( http_transport_t *transport, int socket );

/*
==============
HTTP_SSL_TransportInitSSL

Initialize transport structure for HTTPS
Returns true on success, false on error
==============
*/
qboolean HTTP_SSL_TransportInitSSL( http_transport_t *transport, int socket, const char *hostname );

/*
==============
HTTP_SSL_TransportConnect

Perform SSL handshake after TCP connect
Returns 1 on success, 0 on need to retry, -1 on error
==============
*/
int HTTP_SSL_TransportConnect( http_transport_t *transport );

/*
==============
HTTP_SSL_TransportRead

Read data from transport (plain or SSL)
Returns bytes read, 0 on would block, -1 on error
==============
*/
int HTTP_SSL_TransportRead( http_transport_t *transport, void *buf, size_t len );

/*
==============
HTTP_SSL_TransportWrite

Write data to transport (plain or SSL)
Returns bytes written, 0 on would block, -1 on error
==============
*/
int HTTP_SSL_TransportWrite( http_transport_t *transport, const void *buf, size_t len );

/*
==============
HTTP_SSL_TransportClose

Close transport and cleanup SSL context if needed
==============
*/
void HTTP_SSL_TransportClose( http_transport_t *transport );

/*
==============
HTTP_SSL_LoadCACertificates

Load CA certificates from system store or embedded bundle
Returns true on success
==============
*/
qboolean HTTP_SSL_LoadCACertificates( void );

/*
==============
HTTP_SSL_ErrorToString
==============
*/
const char *HTTP_SSL_ErrorToString( int error_code );

#endif // NET_HTTP_SSL_H
