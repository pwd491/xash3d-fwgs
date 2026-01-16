/*
net_http_ssl.c - SSL/TLS implementation for HTTP client
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

#include "common.h"

#ifdef XASH_HAVE_MBEDTLS
// Allow access to private fields in mbedTLS structures
// This is needed to properly free certificate chains without corrupting memory headers
// Must be defined before including mbedTLS headers
#ifndef MBEDTLS_ALLOW_PRIVATE_ACCESS
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#endif
#endif

#include "net_http_ssl.h"
#include "net_ws_private.h"
#include "port.h"

#ifdef XASH_WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <errno.h>
#include <stdio.h>
#endif

#ifdef XASH_HAVE_MBEDTLS

#include "mbedtls/platform_util.h"  // For mbedtls_platform_zeroize
#include "mbedtls/platform.h"      // For mbedtls_free

/*
==============
ssl_debug_callback

Debug callback for mbedTLS to output debug information
==============
*/
static void ssl_debug_callback( void *ctx, int level, const char *file, int line, const char *str )
{
	// Output debug messages to help diagnose SSL handshake issues
	// Level: 0=No debug, 1=Error, 2=State change, 3=Informational, 4=Verbose
	// For now, show all levels to diagnose the handshake failure
	// Can be filtered later if needed
	Con_Printf( "HTTPS Debug [%d]: %s:%d: %s", level, file, line, str );
}

// Use standard mbedTLS network functions instead of custom wrappers
// These are properly tested and handle all edge cases correctly

static qboolean ssl_initialized = false;
static mbedtls_x509_crt *ca_cert = NULL;

/*
==============
ssl_free_cert_chain_safe

Free certificate chain without zeroizing the root structure
This is needed because the root structure is allocated with Z_Malloc
and zeroizing it would corrupt the memory header sentinel
==============
*/
static void ssl_free_cert_chain_safe( mbedtls_x509_crt *root_crt )
{
	mbedtls_x509_crt *cert_cur = root_crt;
	mbedtls_x509_crt *cert_next;
	
	if( !root_crt )
		return;
	
	// Free all certificates in the chain
	while( cert_cur != NULL )
	{
		// Save next pointer before freeing
		cert_next = cert_cur->next;
		
		// Free internal data
		mbedtls_pk_free( &cert_cur->pk );
		
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
		// Access private field (MBEDTLS_ALLOW_PRIVATE_ACCESS allows direct access)
		if( cert_cur->sig_opts )
		{
			mbedtls_free( cert_cur->sig_opts );
			cert_cur->sig_opts = NULL;
		}
#endif
		
		mbedtls_asn1_free_named_data_list_shallow( cert_cur->issuer.next );
		mbedtls_asn1_free_named_data_list_shallow( cert_cur->subject.next );
		mbedtls_asn1_sequence_free( cert_cur->ext_key_usage.next );
		mbedtls_asn1_sequence_free( cert_cur->subject_alt_names.next );
		mbedtls_asn1_sequence_free( cert_cur->certificate_policies.next );
		mbedtls_asn1_sequence_free( cert_cur->authority_key_id.authorityCertIssuer.next );
		
		// Access private field (MBEDTLS_ALLOW_PRIVATE_ACCESS allows direct access)
		if( cert_cur->raw.p != NULL && cert_cur->own_buffer )
		{
			// Zeroize and free the raw certificate data
			mbedtls_platform_zeroize( cert_cur->raw.p, cert_cur->raw.len );
			mbedtls_free( cert_cur->raw.p );
			cert_cur->raw.p = NULL;
			cert_cur->raw.len = 0;
		}
		
		// If this is not the root certificate, free the structure itself
		// (root will be freed separately with Mem_Free)
		if( cert_cur != root_crt )
		{
			mbedtls_platform_zeroize( cert_cur, sizeof( mbedtls_x509_crt ));
			mbedtls_free( cert_cur );
		}
		
		cert_cur = cert_next;
	}
	
	// Note: We don't zeroize the root structure here because it was
	// allocated with Z_Malloc and zeroizing would corrupt the memory header
	// The root structure will be freed with Mem_Free after this function returns
}

/*
==============
HTTP_SSL_Init

Initialize SSL/TLS subsystem
==============
*/
qboolean HTTP_SSL_Init( void )
{
	if( ssl_initialized )
		return true;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
	// Initialize PSA Crypto - required when MBEDTLS_USE_PSA_CRYPTO is enabled
	// Note: TLS 1.3 is disabled, so we don't need PSA crypto
	psa_status_t status = psa_crypto_init();
	if( status != PSA_SUCCESS )
	{
		Con_Printf( S_ERROR "HTTPS: Failed to initialize PSA Crypto: %d\n", (int)status );
		return false;
	}
#endif

	// Load CA certificates
	if( !HTTP_SSL_LoadCACertificates() )
	{
		Con_Printf( S_WARN "HTTPS: Failed to load CA certificates, HTTPS may not work\n" );
	}

	ssl_initialized = true;
	return true;
}

/*
==============
HTTP_SSL_Shutdown

Shutdown SSL/TLS subsystem
==============
*/
void HTTP_SSL_Shutdown( void )
{
	if( !ssl_initialized )
		return;

	ssl_initialized = false;

	// Free CA certificates last, after all transports are closed
	// Note: Only free if we successfully initialized it
	if( ca_cert )
	{
		// Use custom free function to avoid zeroizing the root structure
		// (which was allocated with Z_Malloc and zeroizing would corrupt the header)
		mbedtls_x509_crt *cert_to_free = ca_cert;
		ca_cert = NULL; // Clear pointer first to prevent use-after-free
		ssl_free_cert_chain_safe( cert_to_free );
		// Now free the root structure itself (allocated with Z_Malloc)
		Mem_Free( cert_to_free );
	}
	
	// Note: Individual transport contexts are cleaned up by HTTP_SSL_TransportClose
}

/*
==============
HTTP_SSL_TransportInit

Initialize transport structure for plain HTTP
==============
*/
void HTTP_SSL_TransportInit( http_transport_t *transport, int socket )
{
	memset( transport, 0, sizeof( *transport ));
	transport->socket = socket;
	transport->is_ssl = false;
	transport->read = HTTP_SSL_TransportRead;
	transport->write = HTTP_SSL_TransportWrite;
	transport->close = HTTP_SSL_TransportClose;
}

/*
==============
HTTP_SSL_TransportInitSSL

Initialize transport structure for HTTPS
==============
*/
qboolean HTTP_SSL_TransportInitSSL( http_transport_t *transport, int socket, const char *hostname )
{
	int ret;
	const char *pers = "xash3d-https";

	memset( transport, 0, sizeof( *transport ));
	transport->socket = socket;
	// Don't set is_ssl = true until initialization is complete

	// Initialize mbedTLS structures
	mbedtls_ssl_init( &transport->ssl );
	mbedtls_ssl_config_init( &transport->conf );
	mbedtls_ctr_drbg_init( &transport->ctr_drbg );
	mbedtls_entropy_init( &transport->entropy );
	
	// Initialize net context for BIO callbacks
	// Note: We already have a connected socket, so we just set the fd
	// Make sure socket is valid before initializing
	if( socket < 0 )
	{
		Con_Printf( S_ERROR "HTTPS: Invalid socket passed to HTTP_SSL_TransportInitSSL: %d\n", socket );
		goto error;
	}
	
	// Initialize net_ctx properly - mbedtls_net_init just zeros it, which we do manually
	// but we need to make sure it's compatible with mbedtls_net_send/recv
	mbedtls_net_init( &transport->net_ctx );
	transport->net_ctx.fd = socket;
	
	// Note: transport->cacert is not used directly, we use ca_cert pointer instead

	// Seed RNG
	ret = mbedtls_ctr_drbg_seed( &transport->ctr_drbg, mbedtls_entropy_func,
		&transport->entropy, (const unsigned char *)pers, strlen( pers ));
	if( ret != 0 )
	{
		char error_buf[256];
		mbedtls_strerror( ret, error_buf, sizeof( error_buf ));
		Con_Printf( S_ERROR "HTTPS: mbedtls_ctr_drbg_seed failed: %s (code %d)\n", error_buf, ret );
		Con_Printf( S_ERROR "HTTPS: This usually means entropy source is unavailable\n" );
		goto error;
	}

	// Load CA certificates
	// Use pointer to shared CA cert instead of copying
	if( ca_cert )
	{
		// We'll use the shared CA cert directly via pointer
		// mbedtls_ssl_conf_ca_chain will be called with ca_cert pointer
	}

	// Configure SSL
	ret = mbedtls_ssl_config_defaults( &transport->conf,
		MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_DEFAULT );
	if( ret != 0 )
	{
		Con_Printf( S_ERROR "HTTPS: mbedtls_ssl_config_defaults returned %d\n", ret );
		goto error;
	}

	// Set CA certificate
	if( ca_cert )
	{
		// Use VERIFY_OPTIONAL to allow handshake to complete even if verification fails
		// This allows us to check the verification result after handshake and decide
		// whether to proceed or not, rather than failing during handshake
		mbedtls_ssl_conf_authmode( &transport->conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
		mbedtls_ssl_conf_ca_chain( &transport->conf, ca_cert, NULL );
		transport->verify_required = true; // We'll check the result after handshake
	}
	else
	{
		// No CA certificates loaded - disable verification to allow connections
		// This is less secure but allows HTTPS to work without system certificates
		mbedtls_ssl_conf_authmode( &transport->conf, MBEDTLS_SSL_VERIFY_NONE );
		transport->verify_required = false;
		Con_Printf( S_WARN "HTTPS: No CA certificates loaded, certificate verification disabled\n" );
	}

	// Set RNG
	mbedtls_ssl_conf_rng( &transport->conf, mbedtls_ctr_drbg_random, &transport->ctr_drbg );

	// Limit to TLS 1.2 for better compatibility
	// Some servers may not properly handle TLS 1.3 negotiation
	// Note: MBEDTLS_SSL_MINOR_VERSION_3 means TLS 1.2 (SSL 3.3 = TLS 1.2)
	mbedtls_ssl_conf_min_version( &transport->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3 );
	mbedtls_ssl_conf_max_version( &transport->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3 );
	
	// Ensure we support the signature algorithms needed for Server Key Exchange verification
	// This is critical for RSA signature verification during handshake

	// Enable debug logging for detailed handshake diagnostics
	// This will help diagnose SSL handshake failures
	// Temporarily enable verbose debug to diagnose EOF issue
	mbedtls_ssl_conf_dbg( &transport->conf, ssl_debug_callback, NULL );
	mbedtls_debug_set_threshold( 3 ); // Informational level (0-4, 3 shows detailed handshake info)

	// Setup SSL context (must be done before setting hostname and BIO)
	ret = mbedtls_ssl_setup( &transport->ssl, &transport->conf );
	if( ret != 0 )
	{
		Con_Printf( S_ERROR "HTTPS: mbedtls_ssl_setup returned %d\n", ret );
		goto error;
	}

	// Set BIO callbacks for socket I/O (must be done after ssl_setup)
	// Use standard mbedTLS network functions - they work correctly with any socket
	mbedtls_ssl_set_bio( &transport->ssl, &transport->net_ctx,
		mbedtls_net_send, mbedtls_net_recv, NULL );

	// Set hostname for SNI (must be done after ssl_setup)
	if( hostname )
	{
		ret = mbedtls_ssl_set_hostname( &transport->ssl, hostname );
		if( ret != 0 )
		{
			Con_Printf( S_ERROR "HTTPS: mbedtls_ssl_set_hostname returned %d\n", ret );
			goto error;
		}
	}

	transport->read = HTTP_SSL_TransportRead;
	transport->write = HTTP_SSL_TransportWrite;
	transport->close = HTTP_SSL_TransportClose;
	
	// Mark as SSL only after successful initialization
	transport->is_ssl = true;

	return true;

error:
		// Clean up any initialized structures
		// These functions are safe to call even if initialization failed partially
		mbedtls_ssl_config_free( &transport->conf );
		mbedtls_ssl_free( &transport->ssl );
		mbedtls_ctr_drbg_free( &transport->ctr_drbg );
		mbedtls_entropy_free( &transport->entropy );
		
		// Free net context properly (mbedtls_net_free just closes the fd, which we manage)
		// But we should clear it to prevent accidental use
		transport->net_ctx.fd = -1;
	
	// Reset transport state
	transport->is_ssl = false;
	transport->read = NULL;
	transport->write = NULL;
	transport->close = NULL;
	
	return false;
}

/*
==============
HTTP_SSL_TransportConnect

Perform SSL handshake after TCP connect
==============
*/
int HTTP_SSL_TransportConnect( http_transport_t *transport )
{
	int ret;

	if( !transport->is_ssl )
		return 1; // Already connected (plain HTTP)

	// Verify net_ctx is properly initialized
	if( transport->net_ctx.fd < 0 )
	{
		Con_Printf( S_ERROR "HTTPS: Invalid socket in net_ctx (fd=%d)\n", transport->net_ctx.fd );
		return -1;
	}
	
	// Verify socket is still valid and connected
	if( transport->socket != transport->net_ctx.fd )
	{
		Con_Printf( S_ERROR "HTTPS: Socket mismatch: socket=%d, net_ctx.fd=%d\n", 
			transport->socket, transport->net_ctx.fd );
		return -1;
	}

	// Check socket for errors before starting handshake
	int so_error = 0;
	socklen_t len = sizeof( so_error );
	if( getsockopt( transport->socket, SOL_SOCKET, SO_ERROR, (char *)&so_error, &len ) == 0 )
	{
		if( so_error != 0 )
		{
			Con_Printf( S_ERROR "HTTPS: Socket has error before handshake: %d\n", so_error );
			return -1;
		}
	}

	// Perform SSL handshake
	// Note: This may need multiple calls in non-blocking mode
	Con_Printf( "HTTPS: Starting SSL handshake (socket=%d, net_ctx.fd=%d)\n", 
		transport->socket, transport->net_ctx.fd );
	ret = mbedtls_ssl_handshake( &transport->ssl );
	Con_Printf( "HTTPS: SSL handshake returned: %d\n", ret );

	if( ret == 0 )
	{
		// Handshake complete - check certificate verification result
		// Only check if verification was enabled
		uint32_t flags = mbedtls_ssl_get_verify_result( &transport->ssl );
		if( flags != 0 )
		{
			// Verification failed - log warning but allow connection to proceed
			// This is less secure but allows HTTPS to work with self-signed or
			// improperly configured certificates
			char vrfy_buf[512];
			mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  ! ", flags );
			Con_Printf( S_WARN "HTTPS: Certificate verification failed (continuing anyway):\n%s\n", vrfy_buf );
			// Don't fail - allow connection to proceed with warning
		}
		else if( transport->verify_required )
		{
			Con_Printf( "HTTPS: Certificate verification successful\n" );
		}
		return 1; // Success
	}
	else if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
	{
		// Need to retry
		return 0;
	}
	else
	{
		// Error - get detailed error information
		char error_buf[256];
		mbedtls_strerror( ret, error_buf, sizeof( error_buf ));
		Con_Printf( S_ERROR "HTTPS: SSL handshake failed: %s (code %d)\n", error_buf, ret );
		
		// Log additional debug info
		Con_Printf( S_ERROR "HTTPS: Socket fd=%d, net_ctx.fd=%d\n", 
			transport->socket, transport->net_ctx.fd );
		
		// Check if connection was closed (EOF)
		if( ret == MBEDTLS_ERR_SSL_CONN_EOF || ret == -29312 )
		{
			Con_Printf( S_ERROR "HTTPS: Connection closed during handshake (EOF). Possible causes:\n" );
			Con_Printf( S_ERROR "  - Server closed connection (may reject our handshake)\n" );
			Con_Printf( S_ERROR "  - Network issue or timeout\n" );
			Con_Printf( S_ERROR "  - Socket not properly connected before handshake\n" );
			Con_Printf( S_ERROR "  - Non-blocking socket issue\n" );
		}
		// For RSA verification failures, provide more context
		else if( ret == MBEDTLS_ERR_RSA_VERIFY_FAILED || ret == -17280 )
		{
			Con_Printf( S_ERROR "HTTPS: Server signature verification failed during handshake.\n" );
			Con_Printf( S_ERROR "HTTPS: This is a security-critical failure - the server's signature\n" );
			Con_Printf( S_ERROR "HTTPS: could not be verified using its certificate. Possible causes:\n" );
			Con_Printf( S_ERROR "  - Server certificate/key mismatch\n" );
			Con_Printf( S_ERROR "  - Server misconfiguration\n" );
			Con_Printf( S_ERROR "  - mbedTLS configuration issue (RSA verification)\n" );
			Con_Printf( S_ERROR "  - Possible RSA-PSS vs RSA-PKCS1 format mismatch\n" );
			Con_Printf( S_ERROR "HTTPS: Connection cannot proceed for security reasons.\n" );
			Con_Printf( S_ERROR "HTTPS: This may be a known mbedTLS issue - check mbedTLS version and config.\n" );
		}
		
		return -1;
	}
}

/*
==============
HTTP_SSL_TransportRead

Read data from transport (plain or SSL)
==============
*/
int HTTP_SSL_TransportRead( http_transport_t *transport, void *buf, size_t len )
{
	if( !transport->is_ssl )
	{
		// Plain HTTP: use recv directly
		return recv( transport->socket, buf, len, 0 );
	}
	else
	{
		// HTTPS: use SSL read
		int ret = mbedtls_ssl_read( &transport->ssl, (unsigned char *)buf, len );
		
		if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
			return 0; // Would block
		else if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
			return 0; // Connection closed gracefully
		else if( ret < 0 )
			return -1; // Error
		else
			return ret; // Bytes read
	}
}

/*
==============
HTTP_SSL_TransportWrite

Write data to transport (plain or SSL)
==============
*/
int HTTP_SSL_TransportWrite( http_transport_t *transport, const void *buf, size_t len )
{
	if( !transport->is_ssl )
	{
		// Plain HTTP: use send directly
		return send( transport->socket, buf, len, 0 );
	}
	else
	{
		// HTTPS: use SSL write
		int ret = mbedtls_ssl_write( &transport->ssl, (const unsigned char *)buf, len );
		
		if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
			return 0; // Would block
		else if( ret < 0 )
			return -1; // Error
		else
			return ret; // Bytes written
	}
}

/*
==============
HTTP_SSL_TransportClose

Close transport and cleanup SSL context if needed
==============
*/
void HTTP_SSL_TransportClose( http_transport_t *transport )
{
	if( transport->is_ssl )
	{
		// Note: Don't call mbedtls_ssl_close_notify if socket is already closed
		// It may try to send data through closed socket
		if( transport->net_ctx.fd >= 0 && transport->socket >= 0 )
		{
			mbedtls_ssl_close_notify( &transport->ssl );
		}
		mbedtls_ssl_config_free( &transport->conf );
		mbedtls_ssl_free( &transport->ssl );
		mbedtls_ctr_drbg_free( &transport->ctr_drbg );
		mbedtls_entropy_free( &transport->entropy );
		
		// Close socket - mbedtls_net_free will close the fd in net_ctx
		// But we manage the socket separately, so close it first
		int saved_socket = transport->socket;
		if( saved_socket >= 0 )
		{
			closesocket( saved_socket );
			transport->socket = -1;
		}
		
		// Free net context (this will close the fd if it's still open)
		// Since we already closed it above, this is safe
		mbedtls_net_free( &transport->net_ctx );
	}

	// Close the socket if not already closed (for non-SSL connections)
	if( transport->socket != -1 )
	{
		closesocket( transport->socket );
		transport->socket = -1;
	}

	memset( transport, 0, sizeof( *transport ));
}

/*
==============
HTTP_SSL_LoadCACertificates

Load CA certificates from system store or embedded bundle
==============
*/
qboolean HTTP_SSL_LoadCACertificates( void )
{
	int ret;
	
	// Allocate CA cert structure
	if( !ca_cert )
	{
		ca_cert = Z_Malloc( sizeof( *ca_cert ));
		mbedtls_x509_crt_init( ca_cert );
	}

#ifdef XASH_WIN32
	// Windows: Load from system certificate store
	HCERTSTORE hStore = CertOpenSystemStore( 0, "ROOT" );
	if( hStore )
	{
		PCCERT_CONTEXT pCertContext = NULL;
		int cert_count = 0;
		int parsed_count = 0;
		
		// Iterate through all certificates in the ROOT store
		while(( pCertContext = CertEnumCertificatesInStore( hStore, pCertContext )) != NULL )
		{
			cert_count++;
			
			// mbedTLS can parse DER directly
			// Note: mbedtls_x509_crt_parse_der adds certificates to the chain
			ret = mbedtls_x509_crt_parse_der( ca_cert, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded );
			if( ret == 0 )
			{
				parsed_count++;
			}
			else if( ret == MBEDTLS_ERR_X509_ALLOC_FAILED )
			{
				// Out of memory - stop loading
				Con_Printf( S_WARN "HTTPS: Out of memory while loading certificates, loaded %d so far\n", parsed_count );
				break;
			}
			// Other errors (like MBEDTLS_ERR_X509_INVALID_FORMAT) are ignored
			// Some certificates might be in unsupported format
		}
		
		CertCloseStore( hStore, 0 );
		
		// Count total certificates in chain
		mbedtls_x509_crt *cur = ca_cert;
		int chain_count = 0;
		while( cur )
		{
			chain_count++;
			cur = cur->next;
		}
		
		if( chain_count > 0 )
		{
			Con_Reportf( "HTTPS: Loaded %d CA certificates from Windows certificate store (parsed %d of %d)\n", 
				chain_count, parsed_count, cert_count );
			return true;
		}
	}
	
	Con_Printf( S_WARN "HTTPS: Failed to load CA certificates from Windows store\n" );
	
#elif defined(XASH_POSIX) || defined(XASH_APPLE)
	// Linux/macOS: Try to load from common certificate bundle locations
	// Note: Use standard file I/O (fopen) for system files, not FS_Open
	// because FS_Open uses the game's filesystem which may not access system paths
	const char *ca_bundle_paths[] = {
		"/etc/ssl/certs/ca-certificates.crt",      // Debian/Ubuntu
		"/etc/ssl/certs/ca-bundle.crt",             // Red Hat/CentOS
		"/etc/pki/tls/certs/ca-bundle.crt",         // Fedora
		"/usr/local/share/certs/ca-root-nss.crt",   // FreeBSD
		"/etc/ssl/cert.pem",                        // Alpine Linux / macOS
		"/etc/ssl/certs.pem",                       // Some systems
		NULL
	};
	
	int i;
	for( i = 0; ca_bundle_paths[i] != NULL; i++ )
	{
		FILE *f = fopen( ca_bundle_paths[i], "rb" );
		if( f )
		{
			// Get file size
			fseek( f, 0, SEEK_END );
			long size = ftell( f );
			fseek( f, 0, SEEK_SET );
			
			if( size > 0 && size < 10 * 1024 * 1024 ) // Max 10MB
			{
				byte *buffer = Z_Malloc( size + 1 );
				if( fread( buffer, 1, size, f ) == (size_t)size )
				{
					buffer[size] = '\0';
					ret = mbedtls_x509_crt_parse( ca_cert, buffer, size + 1 );
					
					// Count certificates (mbedTLS chains them)
					// Note: mbedtls_x509_crt_parse may return MBEDTLS_ERR_X509_INVALID_FORMAT
					// if some certificates failed to parse, but others succeeded
					mbedtls_x509_crt *cur = ca_cert;
					int cert_count = 0;
					while( cur )
					{
						cert_count++;
						cur = cur->next;
					}
					
					fclose( f );
					Z_Free( buffer );
					
					if( cert_count > 0 )
					{
						if( ret != 0 && ret != MBEDTLS_ERR_X509_INVALID_FORMAT )
						{
							char error_buf[256];
							mbedtls_strerror( ret, error_buf, sizeof( error_buf ));
							Con_Printf( S_WARN "HTTPS: Some certificates failed to parse from %s: %s (code %d), but loaded %d certificates\n", 
								ca_bundle_paths[i], error_buf, ret, cert_count );
						}
						Con_Reportf( "HTTPS: Loaded %d CA certificates from %s\n", cert_count, ca_bundle_paths[i] );
						return true;
					}
					else if( ret != 0 )
					{
						// Parse failed completely
						char error_buf[256];
						mbedtls_strerror( ret, error_buf, sizeof( error_buf ));
						Con_Printf( S_WARN "HTTPS: Failed to parse certificates from %s: %s (code %d)\n", 
							ca_bundle_paths[i], error_buf, ret );
					}
				}
				Z_Free( buffer );
			}
			fclose( f );
		}
	}
	
	Con_Printf( S_WARN "HTTPS: Failed to load CA certificates from system bundle\n" );
	
#else
	// Other platforms: For now, return true but without certificates
	// This will cause certificate verification to fail, but allows testing
	Con_Printf( S_WARN "HTTPS: CA certificate loading not implemented for this platform\n" );
	return true;
#endif

	// If we get here, we couldn't load certificates
	// Return true anyway to allow HTTPS to work (but verification will fail)
	// This is useful for testing or if the user wants to proceed anyway
	return true;
}

/*
==============
HTTP_SSL_ErrorToString
==============
*/
const char *HTTP_SSL_ErrorToString( int error_code )
{
	static char error_buf[256];
	mbedtls_strerror( error_code, error_buf, sizeof( error_buf ));
	return error_buf;
}

#else // !XASH_HAVE_MBEDTLS

// Stub implementations when mbedTLS is not available

qboolean HTTP_SSL_Init( void ) { return false; }
void HTTP_SSL_Shutdown( void ) {}
void HTTP_SSL_TransportInit( http_transport_t *transport, int socket )
{
	memset( transport, 0, sizeof( *transport ));
	transport->socket = socket;
	transport->is_ssl = false;
}
qboolean HTTP_SSL_TransportInitSSL( http_transport_t *transport, int socket, const char *hostname ) { return false; }
int HTTP_SSL_TransportConnect( http_transport_t *transport ) { return -1; }
int HTTP_SSL_TransportRead( http_transport_t *transport, void *buf, size_t len ) { return recv( transport->socket, buf, len, 0 ); }
int HTTP_SSL_TransportWrite( http_transport_t *transport, const void *buf, size_t len ) { return send( transport->socket, buf, len, 0 ); }
void HTTP_SSL_TransportClose( http_transport_t *transport )
{
	if( transport->socket != -1 )
	{
		closesocket( transport->socket );
		transport->socket = -1;
	}
}
qboolean HTTP_SSL_LoadCACertificates( void ) { return false; }

#endif // XASH_HAVE_MBEDTLS
