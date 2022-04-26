/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	FILE *fp;
	FILE *fet;	// encrypt text file
	FILE *fdt;	// decrypt text file
	FILE *fek;	// encrypt key file
	FILE *fdk;	// decrypt key file
	char plaintext[64] = {0,};
	char enctext[64] = {0,};
	char enckey[64] = {0,};
	int len = 64;

	res = TEEC_InitializeContext(NULL, &ctx);
	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 0;
	
	//encrypting
	if (strcmp(argv[1], "-e") == 0) {

		//read text file(argev[2] = plaintext)
		fp = fopen(argv[2], "r");
		if(fp == NULL){
			printf("Fail!\n");
			return 1;	
		}
		fgets(plaintext, sizeof(plaintext), fp);
		fclose(fp);

		memcpy(op.params[0].tmpref.buffer, plaintext, len);

		//encrypt
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
				 	&err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	
		
		memcpy(enctext, op.params[0].tmpref.buffer, len);
		printf("Encrypt text: %s\n", enctext);

		//write encrypt_text file
		fet = fopen("/root/encrypt_text.txt", "w");
		fprintf(fet, enctext);
		fclose(fet);
		
		//write encrypt_key file
		fek = fopen("/root/encrypt_key.txt" ,"w");
		fprintf(fek, "%d", op.params[1].value.a);
		fclose(fek);

		printf("Encrypt key: %d\n", op.params[1].value.a);

	}

	else if (strcmp(argv[1], "-d") == 0) {

		//read text file(encrypt_text = argv[2])
		fdt = fopen(argv[2], "r");
		if(fdt == NULL){
			printf("Fail!\n");
			return 1;
		}
		fgets(enctext, sizeof(enctext), fdt);
		fclose(fdt);

		//read key file(encrypt_key = argv[3])
		fdk = fopen(argv[3], "r");
		if(fdk == NULL){
			printf("Fail!\n");
			return 1;
		}
		fgets(enckey, sizeof(enckey), fdk);
		op.params[1].value.a = atoi(enckey);
		fclose(fdk);
		
		memcpy(op.params[0].tmpref.buffer, enctext, len);
		
		//decrypt
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	
		//write decrypt text file
		memcpy(plaintext, op.params[0].tmpref.buffer, len);

		printf("Decrypt text: %s\n", plaintext);

		fdt = fopen("/root/decrypt_text.txt", "w");
		fprintf(fdt, plaintext);
		fclose(fdt);
	}
	

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
