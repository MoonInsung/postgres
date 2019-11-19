/*-------------------------------------------------------------------------
 *
 * kmgr.h
 *	  Key management module for transparent data encryption
 *
 * Portions Copyright (c) 2019, PostgreSQL Global Development Group
 *
 * src/include/storage/kmgr.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef KMGR_H
#define KMGR_H

#include "storage/relfilenode.h"
#include "storage/bufpage.h"

/* Size of HMAC key is the same as the length of hash, we use SHA-256 */
#define TDE_HMAC_KEY_SIZE		32

/* SHA-256 results 256 bits HMAC */
#define TDE_HMAC_SIZE			32

/* Size of key encryption key (KEK), which is always AES-256 key */
#define TDE_KEK_SIZE			32

/*
 * Size of the derived key from passphrase. It consists of KEK and HMAC key.
 */
#define TDE_KEK_DERIVED_KEY_SIZE	(TDE_KEK_SIZE + TDE_HMAC_KEY_SIZE)

/*
 * Iteration count of password based key derivation. NIST recommends that
 * minimum iteration count is 1000.
 */
#define TDE_KEK_DEVIRATION_ITER_COUNT	100000

/*
 * Size of salt for password based key derivation. NIST recommended that
 * salt size is at least 16 bytes
 */
#define TDE_KEK_DEVIRATION_SALT_SIZE	64

/*
 * Max size of data encryption key. We support AES-128 and AES-256, the
 * maximum  key size is 32.
 */
#define TDE_MAX_DEK_SIZE			32

/* Key wrapping appends the initial 64 bit value */
#define TDE_DEK_WRAP_VALUE_SIZE		8

/* Wrapped key size is n+1 value */
#define TDE_MAX_WRAPPED_DEK_SIZE		(TDE_MAX_DEK_SIZE + TDE_DEK_WRAP_VALUE_SIZE)

#define TDE_MAX_PASSPHRASE_LEN		1024

typedef unsigned char keydata_t;

typedef struct WrappedEncKeyWithHmac
{
	keydata_t key[TDE_MAX_WRAPPED_DEK_SIZE];
	keydata_t hmac[TDE_HMAC_SIZE];
} WrappedEncKeyWithHmac;

typedef struct KmgrBootstrapInfo
{
	WrappedEncKeyWithHmac relEncKey;
	WrappedEncKeyWithHmac walEncKey;
	keydata_t kekSalt[TDE_KEK_DEVIRATION_SALT_SIZE];
} KmgrBootstrapInfo;

/* GUC variable */
extern char *cluster_passphrase_command;

extern KmgrBootstrapInfo *BootStrapKmgr(int bootstrap_data_encryption_cipher);
extern void InitializeKmgr(void);
extern const char *KmgrGetRelationEncryptionKey(void);
extern const char *KmgrGetWALEncryptionKey(void);

extern const char *GetBackendKey(void);

#endif /* KMGR_H */
