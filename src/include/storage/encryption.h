/*-------------------------------------------------------------------------
 *
 * encryption.h
 *	  Cluster encryption functions.
 *
 * Portions Copyright (c) 2019, PostgreSQL Global Development Group
 *
 * src/include/storage/encryption.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "access/xlogdefs.h"
#include "storage/bufpage.h"
#include "storage/enc_cipher.h"
#include "storage/enc_common.h"
#include "storage/fd.h"

#define DataEncryptionEnabled() \
	(data_encryption_cipher > TDE_ENCRYPTION_OFF)

/* Cluster encryption doesn't encrypt VM and FSM */
#define EncryptForkNum(forknum) \
	((forknum) == MAIN_FORKNUM || (forknum) == INIT_FORKNUM)

/*
 * The encrypted data is a series of blocks of size ENCRYPTION_BLOCK.
 * Initialization vector(IV) is the same size of cipher block.
 */
#define ENC_BLOCK_SIZE 16
#define ENC_IV_SIZE		(ENC_BLOCK_SIZE)

/*
 * Maximum encryption key size is used by AES-256.
 */
#define ENC_MAX_ENCRYPTION_KEY_SIZE	32

/*
 * The size in byte for counter of AES-CTR mode in nonce.
 */
#define ENC_WAL_AES_COUNTER_SIZE 4
#define ENC_BUFFER_AES_COUNTER_SIZE 4

/* bufenc.c */
extern void DecryptBufferBlock(BlockNumber blocknum, Page page);
extern void EncryptBufferBlock(BlockNumber blocknum, Page page);

/* walenc.c */
extern char *EncryptXLog(char *page, Size nbytes, XLogSegNo segno,
						uint32 offset);
extern void DecryptXLog(char *page, Size nbytes, XLogSegNo segno,
						uint32 offset);

/* bufenc.c */
extern void EncryptionTempBlock(const char *input, char *output, int size,
								off_t curOffset, File ivFile, bool newIV);
extern void DecryptionTempBlock(const char *input, char *output, int size,
								off_t curOffset, File ifVile);

#endif							/* ENCRYPTION_H */
