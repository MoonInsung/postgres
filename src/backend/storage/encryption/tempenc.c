/*-------------------------------------------------------------------------
 *
 * tempenc.c
 *
 * Copyright (c) 2020, PostgreSQL Global Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/storage/encryption/tempenc.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "storage/bufpage.h"
#include "storage/encryption.h"
#include "storage/kmgr.h"
#include "pgstat.h"

static char temp_block_iv_value[ENC_IV_SIZE];

static void get_temp_block_iv(File ivFile, off_t curOffset);
static void set_temp_block_iv(File ivFile, off_t curOffset);

void
EncryptionTempBlock(const char *input, char *output, int size,
					off_t curOffset, File ivFile, bool newIV)
{
	/*
	if (curOffset % BLCKSZ != 0)
		elog(WARNING,"enccurOFfset[%lu]",curOffset);
	*/
	if (size <= 0)
		return;

	if (newIV)
		set_temp_block_iv(ivFile, curOffset);
	else
		get_temp_block_iv(ivFile, curOffset);
	
	pg_encrypt(input,
			   output,
			   size,
			   KmgrGetTempFileEncryptionKey(),
			   temp_block_iv_value);
}

void
DecryptionTempBlock(const char *input, char *output, int size,
					off_t curOffset, File ivFile)
{	
	/*
	if (curOffset % BLCKSZ != 0)
	{
		elog(WARNING,"deccurOFfset[%lu][%d]",curOffset,size);
	}
	*/
	
	if (size <= 0 )
		return;

	get_temp_block_iv(ivFile, curOffset);

	pg_decrypt(input,
			   output,
			   size,
			   KmgrGetTempFileEncryptionKey(),
			   temp_block_iv_value);
}

static void
get_temp_block_iv(File ivFile, off_t curOffset)
{
	int nbytes;
	off_t offset = (curOffset/(off_t)BLCKSZ) * ENC_IV_SIZE;

	nbytes = FileRead(ivFile,
					  temp_block_iv_value,
					  ENC_IV_SIZE,
					  offset,
					  WAIT_EVENT_BUFFILE_READ);

	Assert(nbytes == ENC_IV_SIZE);
}

static void
set_temp_block_iv(File ivFile, off_t curOffset)
{
	int nbytes;
	off_t offset = (curOffset/(off_t)BLCKSZ) * ENC_IV_SIZE;

	if (!pg_strong_random(temp_block_iv_value,
						  ENC_IV_SIZE))
		ereport(ERROR,
				(errmsg("failed to generate temp file IV value")));

	nbytes = FileWrite(ivFile,
					   temp_block_iv_value,
					   ENC_IV_SIZE,
					   offset,
					   WAIT_EVENT_BUFFILE_WRITE);

	Assert(nbytes == ENC_IV_SIZE);
}

