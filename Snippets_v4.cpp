#include "Snippets_v4.h"

#pragma once

#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/rc4.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/seed.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define uchar unsigned char

namespace VP_CRYPTO {

    namespace VP_AES {

        // AES

        void INCREMENT_COUNTER(unsigned char* counter, int position) {

            if (position < 0)
                return;

            if (counter[position] == 0xFF)
            {
                counter[position] = 0x00;
                INCREMENT_COUNTER(counter, position - 1);
                return;
            }
            counter[position] ++;

            return;
        }

        void ADD_PADDING(unsigned char** data, int& dataLen, int blockSize) {

            int padblk_nr = blockSize - (dataLen % blockSize);

            if (padblk_nr == 0) {

                dataLen += blockSize;
                unsigned char* tmp = new unsigned char[dataLen];
                strcpy((char*)tmp, (char*)(*data));
                *data = tmp;

                for (int i = 1; i <= blockSize; i++)
                    (*data)[dataLen - i] = blockSize;
            }
            else {

                dataLen += padblk_nr;
                unsigned char* tmp = new unsigned char[dataLen];
                strcpy((char*)tmp, (char*)(*data));
                *data = tmp;

                for (int i = 1; i <= padblk_nr; i++)
                    (*data)[dataLen - i] = padblk_nr;
            }

            return;
        }

        void REMOVE_PADDING(unsigned char** data, int& dataLen, int blockSize) {

            int i = 1;
            char last = (*data)[dataLen - i];
            char aux = last;

            while (aux == last) {

                i++;
                last = (*data)[dataLen - i];
            }

            i--;

            unsigned char* tmp = new unsigned char[dataLen];
            memcpy((char*)tmp, (char*)(*data), dataLen - i);
            *data = tmp;
            (*data)[dataLen - i] = '\0';
            dataLen = dataLen - i;
        }

        void GENERATE_SALT(int passLength, unsigned char** salt, int& saltLength) {

            saltLength = 8 + 8 - passLength;
            (*salt) = new unsigned char[saltLength];

            if ((*salt) == NULL)
                return;

            RAND_bytes(*salt, saltLength);
        }

        //----// AES-ECB
        void AES_ENC_ECB(unsigned char** pData, int& dataLen, unsigned char* userkey,
            unsigned char** encData) {

            AES_KEY aesKey;
            unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
            int offset = 0;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            ADD_PADDING(pData, dataLen, AES_BLOCK_SIZE);

            (*encData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                memcpy(inblk, (*pData) + offset, AES_BLOCK_SIZE);
                AES_encrypt(inblk, outblk, &aesKey);

                memcpy((*encData) + offset, outblk, AES_BLOCK_SIZE);

                offset += AES_BLOCK_SIZE;
            }
        }

        void AES_DEC_ECB(unsigned char** encData, int& dataLen, unsigned char* userkey,
            unsigned char** decData) {

            AES_KEY aesKey;
            unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
            int offset = 0;

            AES_set_decrypt_key(userkey, 16 * 8, &aesKey);

            (*decData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                memcpy(inblk, (*encData) + offset, AES_BLOCK_SIZE);
                AES_decrypt(inblk, outblk, &aesKey);

                memcpy((*decData) + offset, outblk, AES_BLOCK_SIZE);

                offset += AES_BLOCK_SIZE;
            }

            REMOVE_PADDING(decData, dataLen, AES_BLOCK_SIZE);
        }

        //----// AES_CTR
        void AES_ENC_CTR(unsigned char** pData, int& dataLen, unsigned char* counter,
            unsigned char* userkey, unsigned char** encData) {

            AES_KEY aesKey;
            unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
            int offset = 0;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            ADD_PADDING(pData, dataLen, AES_BLOCK_SIZE);

            (*encData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                memcpy(inblk, (*pData) + offset, AES_BLOCK_SIZE);
                AES_encrypt(counter, outblk, &aesKey);

                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    outblk[i] = outblk[i] ^ inblk[i];

                memcpy((*encData) + offset, outblk, AES_BLOCK_SIZE);

                INCREMENT_COUNTER(counter, AES_BLOCK_SIZE - 1);
                offset += AES_BLOCK_SIZE;
            }
        }

        void AES_DEC_CTR(unsigned char** encData, int& dataLen, unsigned char* counter,
            unsigned char* userkey, unsigned char** decData) {

            AES_KEY aesKey;
            unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
            int offset = 0;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            (*decData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                memcpy(inblk, (*encData) + offset, AES_BLOCK_SIZE);
                AES_encrypt(counter, outblk, &aesKey);

                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    outblk[i] = outblk[i] ^ inblk[i];

                memcpy((*decData) + offset, outblk, AES_BLOCK_SIZE);

                INCREMENT_COUNTER(counter, AES_BLOCK_SIZE - 1);
                offset += AES_BLOCK_SIZE;
            }

            REMOVE_PADDING(decData, dataLen, AES_BLOCK_SIZE);
        }

        //----// AES_CBC
        void AES_ENC_CBC(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** encData) {

            AES_KEY aesKey;
            unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
            int offset = 0;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            ADD_PADDING(pData, dataLen, AES_BLOCK_SIZE);

            (*encData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                memcpy(inblk, (*pData) + offset, AES_BLOCK_SIZE);
                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    inblk[i] = inblk[i] ^ iv[i];

                AES_encrypt(inblk, outblk, &aesKey);
                memcpy((*encData) + offset, outblk, AES_BLOCK_SIZE);

                memcpy(iv, outblk, AES_BLOCK_SIZE);
                offset += AES_BLOCK_SIZE;
            }
        }

        void AES_DEC_CBC(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** decData) {

            AES_KEY aesKey;
            unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
            int offset = 0;

            AES_set_decrypt_key(userkey, 16 * 8, &aesKey);

            (*decData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                memcpy(inblk, (*encData) + offset, AES_BLOCK_SIZE);

                AES_decrypt(inblk, outblk, &aesKey);

                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    outblk[i] = outblk[i] ^ iv[i];

                memcpy((*decData) + offset, outblk, AES_BLOCK_SIZE);

                memcpy(iv, inblk, AES_BLOCK_SIZE);
                offset += AES_BLOCK_SIZE;
            }

            REMOVE_PADDING(decData, dataLen, AES_BLOCK_SIZE);
        }

        //----// AES_OFB
        void AES_ENC_OFB(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** encData) {

            AES_KEY aesKey;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            ADD_PADDING(pData, dataLen, AES_BLOCK_SIZE);

            unsigned char temp[AES_BLOCK_SIZE], inblk[AES_BLOCK_SIZE];
            unsigned char* out = (unsigned char*)malloc(AES_BLOCK_SIZE);
            int offset = 0;

            (*encData) = (unsigned char*)malloc(dataLen);

            while (offset < dataLen) {

                AES_encrypt(iv, out, &aesKey);
                memcpy(temp, out, AES_BLOCK_SIZE);
                memcpy(inblk, (*pData) + offset, AES_BLOCK_SIZE);

                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    inblk[i] = inblk[i] ^ out[i];

                memcpy((*encData) + offset, inblk, AES_BLOCK_SIZE);

                memcpy(iv, temp, AES_BLOCK_SIZE);
                offset += AES_BLOCK_SIZE;
            }
        }

        void AES_DEC_OFB(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** decData) {

            AES_KEY aesKey;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            unsigned char temp[AES_BLOCK_SIZE], inblk[AES_BLOCK_SIZE];
            unsigned char* out = (unsigned char*)malloc(AES_BLOCK_SIZE);
            int offset = 0;

            (*decData) = (unsigned char*)malloc(dataLen);

            while (offset < dataLen) {

                AES_encrypt(iv, out, &aesKey);
                memcpy(temp, out, AES_BLOCK_SIZE);
                memcpy(inblk, (*encData) + offset, AES_BLOCK_SIZE);

                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    inblk[i] = inblk[i] ^ out[i];

                memcpy((*decData) + offset, inblk, AES_BLOCK_SIZE);

                memcpy(iv, temp, AES_BLOCK_SIZE);
                offset += AES_BLOCK_SIZE;
            }

            REMOVE_PADDING(decData, dataLen, AES_BLOCK_SIZE);
        }

        //----// AES_CFB
        void AES_ENC_CFB(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** encData) {

            AES_KEY aesKey;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            ADD_PADDING(pData, dataLen, AES_BLOCK_SIZE);

            unsigned char temp[AES_BLOCK_SIZE], inblk[AES_BLOCK_SIZE];
            unsigned char* out = new unsigned char[AES_BLOCK_SIZE];
            int offset = 0;

            (*encData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                AES_encrypt(iv, out, &aesKey);
                memcpy(inblk, (*pData) + offset, AES_BLOCK_SIZE);

                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    inblk[i] = inblk[i] ^ out[i];

                memcpy(temp, inblk, AES_BLOCK_SIZE);
                memcpy((*encData) + offset, inblk, AES_BLOCK_SIZE);

                memcpy(iv, temp, AES_BLOCK_SIZE);
                offset += AES_BLOCK_SIZE;
            }
        }

        void AES_DEC_CFB(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** decData) {

            AES_KEY aesKey;

            AES_set_encrypt_key(userkey, 16 * 8, &aesKey);

            unsigned char temp[AES_BLOCK_SIZE], inblk[AES_BLOCK_SIZE];
            unsigned char* out = new unsigned char[AES_BLOCK_SIZE];
            int offset = 0;

            (*decData) = new unsigned char[dataLen];

            while (offset < dataLen) {

                AES_encrypt(iv, out, &aesKey);
                memcpy(inblk, (*encData) + offset, AES_BLOCK_SIZE);

                for (int i = 0; i < AES_BLOCK_SIZE; i++)
                    inblk[i] = inblk[i] ^ out[i];

                memcpy(temp, inblk, AES_BLOCK_SIZE);
                memcpy((*decData) + offset, inblk, AES_BLOCK_SIZE);

                memcpy(iv, temp, AES_BLOCK_SIZE);
                offset += AES_BLOCK_SIZE;
            }

            REMOVE_PADDING(decData, dataLen, AES_BLOCK_SIZE);
        }

        //----// RC4
        void RC4_ENC(unsigned char** inputData, int& inputDataLen, unsigned char* key, unsigned char** encData) {

            (*encData) = (unsigned char*)malloc(inputDataLen);

            RC4_KEY rc4Key;
            RC4_set_key(&rc4Key, strlen((const char*)*key), key);
            RC4(&rc4Key, inputDataLen, (*inputData), (*encData));
        }

        void RC4_DEC(unsigned char** encData, int& encDataLen, unsigned char* key, unsigned char** decData) {

            (*decData) = (unsigned char*)malloc(encDataLen);

            RC4_KEY rc4Key;
            RC4_set_key(&rc4Key, strlen((const char*)*key), key);
            RC4(&rc4Key, encDataLen, (*encData), (*decData));
        }

        //----// DES3
        void DE3_ENC_ECB(unsigned char* inData, unsigned char* outData, int length, DES_key_schedule* pKs1,
            DES_key_schedule* pKs2, DES_key_schedule* pKs3, int operation) {

            int offset = 0;
            DES_cblock cblockIN;
            DES_cblock cblockOut;
            int cblock_size = sizeof(DES_cblock);
            while (offset < length)
            {
                memcpy(cblockIN, inData + offset, cblock_size);
                DES_ecb3_encrypt(&cblockIN, &cblockOut, pKs1, pKs2, pKs3, operation);
                memcpy(outData + offset, cblockOut, cblock_size);
                offset += cblock_size;
            }
        }

        //----// EXAMPLE
        void aes_example() {

            uchar* plaintext = (uchar*)"Acesta este un test";
            int plaintext_length = 20;
            uchar* key = (uchar*)"0001020304050607";
            uchar* iv = new unsigned char[16];
            memset(iv, 0, 16);
            uchar* counter = new unsigned char[16];
            memset(counter, 0, 16);
            uchar* ciphertext = nullptr;
            int ciphertext_length;

            uchar* plaintext_copy = new uchar[plaintext_length];
            strcpy((char*)plaintext_copy, (char*)plaintext);
            AES_ENC_ECB(&plaintext, plaintext_length, key, &ciphertext);
            memset(plaintext_copy, 0, plaintext_length);
            AES_DEC_ECB(&ciphertext, plaintext_length, key, &plaintext_copy);

            plaintext_copy = new uchar[plaintext_length];
            strcpy((char*)plaintext_copy, (char*)plaintext);
            AES_ENC_CTR(&plaintext, plaintext_length, counter, key, &ciphertext);
            memset(plaintext_copy, 0, plaintext_length);
            memset(counter, 0, 16);
            AES_DEC_CTR(&ciphertext, plaintext_length, counter, key, &plaintext_copy);

            plaintext_copy = new uchar[plaintext_length];
            strcpy((char*)plaintext_copy, (char*)plaintext);
            memset(iv, 0, 16);
            AES_ENC_CBC(&plaintext, plaintext_length, iv, key, &ciphertext);
            memset(plaintext_copy, 0, plaintext_length);
            memset(iv, 0, 16);
            AES_DEC_CBC(&ciphertext, plaintext_length, iv, key, &plaintext_copy);

            plaintext_copy = new uchar[plaintext_length];
            strcpy((char*)plaintext_copy, (char*)plaintext);
            memset(iv, 0, 16);
            AES_ENC_OFB(&plaintext, plaintext_length, iv, key, &ciphertext);
            memset(plaintext_copy, 0, plaintext_length);
            memset(iv, 0, 16);
            AES_DEC_OFB(&ciphertext, plaintext_length, iv, key, &plaintext_copy);

            plaintext_copy = new uchar[plaintext_length];
            strcpy((char*)plaintext_copy, (char*)plaintext);
            memset(iv, 0, 16);
            AES_ENC_CFB(&plaintext, plaintext_length, iv, key, &ciphertext);
            memset(plaintext_copy, 0, plaintext_length);
            memset(iv, 0, 16);
            AES_DEC_CFB(&ciphertext, plaintext_length, iv, key, &plaintext_copy); // dupa un block de 16 nu mai face bine

            /*plaintext_copy = new uchar[plaintext_length];
            plaintext_length = 20;
            strcpy((char*)plaintext_copy, (char*)plaintext);
            RC4_ENC(&plaintext, plaintext_length, key, &ciphertext);
            memset(plaintext_copy, 0, plaintext_length);
            RC4_DEC(&ciphertext, plaintext_length, key, &plaintext_copy);*/
        }
    }

    namespace VP_AES_EVP {
        // AES EVP

        unsigned char* AES_ENC_EVP(unsigned char* plaintext, int plaintext_length, unsigned char* key,
            unsigned char* iv, int* ciphertext_length, const EVP_CIPHER* evp_chiper) {

            // key[] = "16/24/32 bytes depending on the cipher used (EVP_aes_256_cbc() => 32)";
            // EVP_des_ede - 3DES with 2 x 8 bytes keys
            // EVE_des_ede3 - 3DES with 3 x 8 bytes keys
            // iv[] = "Most of the times same as block size. Use AES_BLOCK_SIZE if unsure.";

            unsigned char* ciphertext = new unsigned char[plaintext_length + AES_BLOCK_SIZE - (plaintext_length % AES_BLOCK_SIZE)];

            EVP_CIPHER_CTX* ctx;
            int temp_length;

            // Context construction and initialization
            ctx = EVP_CIPHER_CTX_new();

            // Encryption initialization
            // change evp_cipher to the desired one
            EVP_EncryptInit_ex(ctx, evp_chiper, NULL, key, iv);

            // Encryption without padding 
            EVP_EncryptUpdate(ctx, ciphertext, ciphertext_length, plaintext, plaintext_length);

            // Last block with padding
            EVP_EncryptFinal_ex(ctx, ciphertext + *ciphertext_length, &temp_length);
            *ciphertext_length += temp_length;

            // Clean-up
            EVP_CIPHER_CTX_free(ctx);

            return ciphertext;
        }

        unsigned char* AES_DEC_EVP(unsigned char* ciphertext, int ciphertext_length, unsigned char* key,
            unsigned char* iv, int* plaintext_length, const EVP_CIPHER* evp_cipher) {

            // key[] = "16/24/32 bytes depending on the cipher used (EVP_aes_256_cbc() => 32)";
            // iv[] = "Most of the times same as block size. Use AES_BLOCK_SIZE if unsure.";

            unsigned char* plaintext = new unsigned char[ciphertext_length];

            EVP_CIPHER_CTX* ctx;
            int temp_length;

            // Context construction and initialization
            ctx = EVP_CIPHER_CTX_new();

            // Decryption initialization
            // change evp_cipher to the desired one
            EVP_DecryptInit_ex(ctx, evp_cipher, NULL, key, iv);

            // Decryption without the last block
            EVP_DecryptUpdate(ctx, plaintext, plaintext_length, ciphertext, ciphertext_length);

            // Last block decryption
            EVP_DecryptFinal_ex(ctx, plaintext + *plaintext_length, &temp_length);
            *plaintext_length += temp_length;

            // Should be a printable string
            plaintext[*plaintext_length] = '\0';

            // Clean-up
            EVP_CIPHER_CTX_free(ctx);

            return plaintext;
        }

        //----// AES EVP EXAMPLE
        void aes_evp_example() {

            uchar* plaintext = (uchar*)"Acesta este un test";
            int plaintext_length = 20;
            uchar* key = (uchar*)"0001020304050607";
            uchar* iv = (uchar*)"0000000000000000";
            uchar* ciphertext = nullptr;
            int ciphertext_length;

            ciphertext = AES_ENC_EVP(plaintext, plaintext_length, key, iv, &ciphertext_length, EVP_aes_128_cbc());

            uchar* plaintext2 = nullptr;
            int plaintext_length2;

            plaintext2 = AES_DEC_EVP(ciphertext, ciphertext_length, key, iv, &plaintext_length2, EVP_aes_128_cbc());

            printf("%s\n", plaintext2);
        }
    }

    namespace VP_HASH {

        // HASH

        unsigned char* HASH(unsigned char* plaintext, int plaintext_length, int iter,
            VP_HASH::DIGEST_METHOD digest_method) {

            unsigned char* hash = nullptr;
            int digest_length;

            // In the first iteration we hash the plaintext with it's own length
            // If we have more the 1 iteration we hash the result

            switch (digest_method)
            {
            case VP_HASH::DIGEST_METHOD::sha1:
                digest_length = SHA_DIGEST_LENGTH;
                hash = new unsigned char[digest_length];

                SHA1(plaintext, plaintext_length, hash);

                for (int i = 1; i < iter; i++)
                    SHA1(hash, digest_length, hash);
                break;
            case VP_HASH::DIGEST_METHOD::sha256:
                digest_length = SHA256_DIGEST_LENGTH;
                hash = new unsigned char[digest_length];

                SHA256(plaintext, plaintext_length, hash);

                for (int i = 1; i < iter; i++)
                    SHA256(hash, digest_length, hash);
                break;
            case VP_HASH::DIGEST_METHOD::sha512:
                digest_length = SHA512_DIGEST_LENGTH;
                hash = new unsigned char[digest_length];

                SHA512(plaintext, plaintext_length, hash);

                for (int i = 1; i < iter; i++)
                    SHA512(hash, digest_length, hash);
                break;
            case VP_HASH::DIGEST_METHOD::sha384:
                digest_length = SHA384_DIGEST_LENGTH;
                hash = new unsigned char[digest_length];

                SHA384(plaintext, plaintext_length, hash);

                for (int i = 1; i < iter; i++)
                    SHA384(hash, digest_length, hash);
                break;
            case VP_HASH::DIGEST_METHOD::sha224:
                digest_length = SHA224_DIGEST_LENGTH;
                hash = new unsigned char[digest_length];

                SHA224(plaintext, plaintext_length, hash);

                for (int i = 1; i < iter; i++)
                    SHA224(hash, digest_length, hash);
                break;
            default:
                return nullptr;
            }

            return hash;
        }

        unsigned char* HASH_EVP(unsigned char* plaintext, int plaintext_length, int iter,
            const EVP_MD* evp_digest_method, unsigned int* digest_length) {

            unsigned char* digest = new unsigned char[EVP_MD_size(evp_digest_method)];

            EVP_MD_CTX* mdctx;

            // Context ...
            mdctx = EVP_MD_CTX_new();

            // Initialization
            EVP_DigestInit_ex(mdctx, evp_digest_method, NULL);

            // Hash calculation
            EVP_DigestUpdate(mdctx, plaintext, plaintext_length);

            // Result return
            EVP_DigestFinal_ex(mdctx, digest, digest_length);

            // If we have more the 1 iteration we hash the result
            for (int i = 1; i < iter; i++) {
                // Hashing the result
                EVP_DigestUpdate(mdctx, digest, *digest_length);

                // Result return
                EVP_DigestFinal_ex(mdctx, digest, digest_length);
            }

            // Clean-up
            EVP_MD_CTX_free(mdctx);

            return digest;
        }

        //----// HASH EXAMPLE
        void hash_example() {

            uchar* plaintext = (uchar*)"Acesta este un test";
            int plaintext_length = 20;
            int iter = 20;

            uchar* hash = HASH(plaintext, plaintext_length, iter, VP_HASH::DIGEST_METHOD::sha256);

            for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                printf("%c", hash[i]);
            } printf("\n");

            unsigned int digest_length;
            uchar* digest = HASH_EVP(plaintext, plaintext_length, iter, EVP_sha256(), &digest_length);

            for (int i = 0; i < digest_length; i++) {
                printf("%c", digest[i]);
            } printf("\n");
        }
    }

    namespace VP_RSA {

        // RSA 

        RSA* RSA_KEY_GENERATION(int bits, int exponent) {

            RSA* rsa_handler = RSA_new();
            BIGNUM* public_exponent = BN_new();

            BN_set_word(public_exponent, exponent);
            while (!RSA_generate_key_ex(rsa_handler, bits, public_exponent, nullptr)) {}

            return rsa_handler;
        }

        unsigned char* RSA_ENCRYPTION(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            PADDING padding, unsigned int* return_code) {

            // ciphertext must always be the same as RSA_size
            unsigned char* ciphertext = nullptr;

            // plaintext_size shouldn't be larger than:
            // - RSA_size - 11 _ PKCS1 padding
            // - RSA_size - 42 _ OAEP padding
            // - RSA_size _ no padding

            switch (padding)
            {
            case VP_RSA::PADDING::RSA_PKCS1:
                ciphertext = new unsigned char[RSA_size(rsa_handler) - 11];
                break;
            case VP_RSA::PADDING::RSA_PKCS1_OAEP:
                ciphertext = new unsigned char[RSA_size(rsa_handler) - 42];
                break;
            case VP_RSA::PADDING::RSA_NO:
                ciphertext = new unsigned char[RSA_size(rsa_handler)];
                break;
            default:
                return nullptr;
            }

            *return_code = RSA_public_encrypt(plaintext_length, plaintext, ciphertext, rsa_handler, (int)padding);

            return ciphertext;
        }

        unsigned char* RSA_DECRYPTION(RSA* rsa_handler, unsigned char* ciphertext,
            PADDING padding, unsigned int* return_code) {
            // plaintext must be large enough to hold the maximal possible decrypted data
            // - RSA_size - 11 _ PKCS1 padding
            // - RSA_size - 42 _ OAEP padding
            // - RSA_size _ no padding

            unsigned char* plaintext = nullptr;

            switch (padding)
            {
            case VP_RSA::PADDING::RSA_PKCS1:
                plaintext = new unsigned char[RSA_size(rsa_handler) - 11];
                break;
            case VP_RSA::PADDING::RSA_PKCS1_OAEP:
                plaintext = new unsigned char[RSA_size(rsa_handler) - 42];
                break;
            case VP_RSA::PADDING::RSA_NO:
                plaintext = new unsigned char[RSA_size(rsa_handler)];
                break;
            default:
                return nullptr;
            }

            // flen should always be RSA_size
            *return_code = RSA_private_decrypt(RSA_size(rsa_handler), ciphertext, plaintext, rsa_handler, (int)padding);

            return plaintext;
        }

        unsigned char* RSA_SIGN_USING_ENCRYPT(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            VP_HASH::DIGEST_METHOD digest_method, PADDING padding, unsigned int* return_code) {

            // the signature must point to RSA_size bytes
            unsigned char* signature = new unsigned char[RSA_size(rsa_handler)];

            unsigned char* hash = VP_HASH::HASH(plaintext, plaintext_length, 1, digest_method);
            int hash_length = 0;

            switch (digest_method)
            {
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha1:
                hash_length = SHA_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha256:
                hash_length = SHA256_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha512:
                hash_length = SHA512_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha384:
                hash_length = SHA384_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha224:
                hash_length = SHA224_DIGEST_LENGTH;
                break;
            default:
                break;
            }

            *return_code = RSA_private_encrypt(hash_length, hash, signature, rsa_handler, (int)padding);

            return signature;
        }

        void RSA_VERIFY_USING_DECRYPT(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            unsigned char* signature, VP_HASH::DIGEST_METHOD digest_method, PADDING padding,
            unsigned int* return_code) {

            int hash_length = 0;

            switch (digest_method)
            {
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha1:
                hash_length = SHA_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha256:
                hash_length = SHA256_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha512:
                hash_length = SHA512_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha384:
                hash_length = SHA384_DIGEST_LENGTH;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha224:
                hash_length = SHA224_DIGEST_LENGTH;
                break;
            default:
                break;
            }

            unsigned char* hash = VP_HASH::HASH(plaintext, plaintext_length, 1, digest_method);
            unsigned char* sig_hash = new unsigned char[hash_length];

            RSA_public_decrypt(RSA_size(rsa_handler), signature, sig_hash, rsa_handler, (int)padding);

            unsigned int status = 1; // 0 - invalid signature; 1 - valid signature

            for (int i = 0; i < hash_length; i++) {
                if (hash[i] != sig_hash[i]) status = 0; break;
            }

            *return_code = status;
        }

        unsigned char* RSA_SIGN(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            VP_HASH::DIGEST_METHOD digest_method, unsigned int* signature_length,
            unsigned int* return_code) {

            // the signature must point to RSA_size bytes
            unsigned char* signature = new unsigned char[RSA_size(rsa_handler)];

            unsigned char* hash = VP_HASH::HASH(plaintext, plaintext_length, 1, digest_method);
            int hash_length = 0;
            int type = 0;

            switch (digest_method)
            {
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha1:
                hash_length = SHA_DIGEST_LENGTH;
                type = NID_sha1;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha256:
                hash_length = SHA256_DIGEST_LENGTH;
                type = NID_sha256;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha512:
                hash_length = SHA512_DIGEST_LENGTH;
                type = NID_sha512;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha384:
                hash_length = SHA384_DIGEST_LENGTH;
                type = NID_sha384;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha224:
                hash_length = SHA224_DIGEST_LENGTH;
                type = NID_sha224;
                break;
            default:
                break;
            }

            //1 on success, 0 otherwise
            *return_code = RSA_sign(type, hash, hash_length, signature, signature_length, rsa_handler);

            return signature;
        }

        void RSA_VERIFY(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length, unsigned char* signature,
            unsigned int signature_length, VP_HASH::DIGEST_METHOD digest_method, unsigned int* return_code) {

            unsigned char* hash = VP_HASH::HASH(plaintext, plaintext_length, 1, digest_method);
            int hash_length = 0;
            int type = 0;

            switch (digest_method)
            {
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha1:
                hash_length = SHA_DIGEST_LENGTH;
                type = NID_sha1;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha256:
                hash_length = SHA256_DIGEST_LENGTH;
                type = NID_sha256;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha512:
                hash_length = SHA512_DIGEST_LENGTH;
                type = NID_sha512;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha384:
                hash_length = SHA384_DIGEST_LENGTH;
                type = NID_sha384;
                break;
            case VP_CRYPTO::VP_HASH::DIGEST_METHOD::sha224:
                hash_length = SHA224_DIGEST_LENGTH;
                type = NID_sha224;
                break;
            default:
                break;
            }

            // returns 1 on successful verification, 0 otherwise
            *return_code = RSA_verify(type, hash, hash_length, signature, signature_length, rsa_handler);
        }

        //----// RSA TO FILE - PKCS1
        void RSA_PUB_PKCS1_TO_FILE(RSA* rsa_handler, const char* filename) {

            BIO* file = BIO_new_file(filename, "wb");
            PEM_write_bio_RSAPublicKey(file, rsa_handler);
            BIO_free(file);
        }

        void RSA_PRV_PKCS1_TO_FILE(RSA* rsa_handler, const char* filename, const EVP_CIPHER* evp_cipher,
            const char* password) {

            BIO* file = BIO_new_file(filename, "wb");
            PEM_write_bio_RSAPrivateKey(file, rsa_handler, evp_cipher /* cipher for encryption */, (unsigned char*)password /* pbkdf */, strlen(password), nullptr, nullptr);
            BIO_free(file);
        }

        //----// RSA TO FILE - PKCS8
        void RSA_PUB_PKCS8_TO_FILE(RSA* rsa_handler, const char* filename) {

            EVP_PKEY* prv = EVP_PKEY_new();
            EVP_PKEY_set1_RSA(prv, rsa_handler);

            BIO* file = BIO_new_file(filename, "wb");
            PEM_write_bio_PUBKEY(file, prv);

            //BIO* file = BIO_new_file("file.pem", "wb");
            //PEM_write_bio_RSA_PUBKEY(file, rsa_handler);

            BIO_free(file);
        }

        void RSA_PRV_PKCS8_TO_FILE(RSA* rsa_handler, const char* filename, const EVP_CIPHER* evp_cipher,
            const char* password) {

            EVP_PKEY* prv = EVP_PKEY_new();
            EVP_PKEY_set1_RSA(prv, rsa_handler);

            BIO* file = BIO_new_file(filename, "wb");
            PEM_write_bio_PrivateKey(file, prv, evp_cipher /* cipher for encryption */, (unsigned char*)password /* pbkdf */, strlen(password), nullptr, nullptr);

            // PEM_write_bio_PKCS8PrivateKey(file, prv, EVP_aes_128_cbc(), (char*)"1234", 4, nullptr, nullptr);

            BIO_free(file);
        }

        //----// RSA FROM FILE - PKCS1
        RSA* RSA_PRV_PKCS1_FROM_FILE(const char* filename, const char* password) {

            BIO* file = BIO_new_file(filename, "rb");
            RSA* rsa_handler = RSA_new();
            PEM_read_bio_RSAPrivateKey(file, &rsa_handler, nullptr, (void*)password);
            BIO_free(file);

            return rsa_handler;
        }

        //----// RSA FROM FILE - PKCS8
        RSA* RSA_PRV_PKCS8_FROM_FILE(const char* filename, const char* password) {

            BIO* file = BIO_new_file(filename, "rb");
            EVP_PKEY* prv = EVP_PKEY_new();

            // PKCS8
            PEM_read_bio_PrivateKey(file, &prv, nullptr, (void*)password);
            RSA* rsa_handler = EVP_PKEY_get1_RSA(prv);
            // 1 - both prv and rsa_handler must be freed
            // 0 - only prv must be freed
            BIO_free(file);

            return rsa_handler;
        }

        //----// RSA UTILS

        BIGNUM* BN_GET_NEXT_PRIME(int start_point) {

            BIGNUM* bn = BN_new();
            BN_CTX* ctx = BN_CTX_new();
            start_point += (start_point + 1) % 2;
            for (;; start_point += 2) {
                BN_set_word(bn, start_point);

                if (BN_is_prime_ex(bn, 512, ctx, NULL))
                    break;
            }

            return bn;
        }

        BIGNUM* BN_GET_PRIME(int start_point) {

            BIGNUM* bn = BN_new();
            BN_CTX* ctx = BN_CTX_new();

            if (start_point % 2 == 0)
                start_point++;
            BN_set_word(bn, start_point);
            while (!BN_is_prime_ex(bn, 512, ctx, NULL))
                start_point += 2;

            return bn;
        }

        int GET_NEXT_PRIME(int start_point) {

            BIGNUM* bn = BN_new();
            BN_CTX* ctx = BN_CTX_new();
            start_point += (start_point + 1) % 2;
            for (;; start_point += 2) {
                BN_set_word(bn, start_point);

                if (BN_is_prime_ex(bn, 512, ctx, NULL))
                    break;
            }

            return start_point;
        }

        int GET_PRIME(int start_point) {

            BIGNUM* bn = BN_new();
            BN_CTX* ctx = BN_CTX_new();

            if (start_point % 2 == 0)
                start_point++;
            BN_set_word(bn, start_point);
            while (!BN_is_prime_ex(bn, 512, ctx, NULL))
                start_point += 2;

            return start_point;
        }

        void RSA_PRINT_CONTENTS(RSA* rsa_handler) {

            BIGNUM* bn = BN_new();
            char* number;

            {
                bn = (BIGNUM*)RSA_get0_n(rsa_handler); // RSA_get0_n - modulus
                number = (char*)malloc(BN_num_bytes(bn));
                number = BN_bn2dec(bn);
                printf("n = %s\n\n", number);
                free(number);
            }

            {
                bn = (BIGNUM*)RSA_get0_e(rsa_handler); // RSA_get0_e - public exponent
                number = (char*)malloc(BN_num_bytes(bn));
                number = BN_bn2dec(bn);
                printf("e = %s\n\n", number);
                free(number);
            }

            {
                bn = (BIGNUM*)RSA_get0_d(rsa_handler); // RSA_get0_d - private exponent
                number = (char*)malloc(BN_num_bytes(bn));
                number = BN_bn2dec(bn);
                printf("d = %s\n\n", number);
                free(number);
            }
        }

        //----// RSA EXAMPLE

        void rsa_example() {

            RSA* rsaKeys = RSA_KEY_GENERATION(2048, 3);

            RSA_PRV_PKCS1_TO_FILE(rsaKeys, "rsaPKCS1.prv", EVP_aes_128_cbc(), "1234");
            RSA_PUB_PKCS1_TO_FILE(rsaKeys, "rsaPKCS1.pub");
            RSA_PRV_PKCS8_TO_FILE(rsaKeys, "rsaPKCS8.prv", EVP_aes_128_cbc(), "1234");
            RSA_PUB_PKCS8_TO_FILE(rsaKeys, "rsaPKCS8.pub");

            rsaKeys = nullptr;

            rsaKeys = RSA_PRV_PKCS1_FROM_FILE("rsaPKCS1.prv", "1234");
            rsaKeys = RSA_PRV_PKCS8_FROM_FILE("rsaPKCS8.prv", "1234");

            unsigned int status;
            uchar* plaintext = (uchar*)"Acesta este un test";
            int plaintext_length = 20;

            uchar* ciphertext = RSA_ENCRYPTION(rsaKeys, plaintext, plaintext_length, PADDING::RSA_PKCS1, &status);

            uchar* plaintext2 = RSA_DECRYPTION(rsaKeys, ciphertext, PADDING::RSA_PKCS1, &status);
            printf("%s\n", plaintext2);

            uchar* sig = RSA_SIGN_USING_ENCRYPT(rsaKeys, plaintext, plaintext_length, VP_HASH::DIGEST_METHOD::sha256, PADDING::RSA_PKCS1_OAEP, &status);
            RSA_VERIFY_USING_DECRYPT(rsaKeys, plaintext, plaintext_length, sig, VP_HASH::DIGEST_METHOD::sha256, PADDING::RSA_PKCS1, &status);
            if (status == 1) printf("Sig verified!\n"); // work in progress!!!

            unsigned int signature_length;
            uchar* signature = RSA_SIGN(rsaKeys, plaintext, plaintext_length, VP_HASH::DIGEST_METHOD::sha256, &signature_length, &status);
            RSA_VERIFY(rsaKeys, plaintext, plaintext_length, signature, signature_length, VP_HASH::DIGEST_METHOD::sha256, &status);
            if (status == 1) printf("Signature verified!\n");

            int num = time(0);
            int prime = GET_NEXT_PRIME(num);
            printf("Number is: %d, Next prime is: %d\n", num, prime);
        }
    }

    namespace VP_EC {
        // EC

        EC_KEY* EC_KEY_GENERATION(int curve_id) {

            EC_KEY* key_pair = EC_KEY_new_by_curve_name(curve_id);
            EC_KEY_generate_key(key_pair);

            // EC_KEY_get0_private_key - returns a BIGNUM
            // EC_KEY_get0_public_key - returns an EC_POINT

            return key_pair;
        }

        EVP_PKEY* EC_KEY_GENERATION_EVP(int evp_curve_id) {

            EVP_PKEY* key_pair = EVP_PKEY_new();
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(evp_curve_id, NULL);
   
            EVP_PKEY_keygen_init(ctx);
            EVP_PKEY_keygen(ctx, &key_pair);
            EVP_PKEY_CTX_free(ctx);

            return key_pair;
        }

        //----// EC TO FILE
        void EC_PRV_TO_FILE(EC_KEY* key_pair, const char* filename, const EVP_CIPHER* evp_cipher,
            const char* password) {

            BIO* file = BIO_new_file(filename, "wb");
            PEM_write_bio_ECPrivateKey(file, key_pair, evp_cipher, (unsigned char*)password, strlen(password), nullptr, nullptr);
            BIO_free(file);
        }

        void EC_PUB_TO_FILE(EC_KEY* key_pair, const char* filename) {

            BIO* file = BIO_new_file(filename, "wb");
            PEM_write_bio_EC_PUBKEY(file, key_pair);
            BIO_free(file);
        }

        //----// EC FROM FILE
        EC_KEY* EC_PRV_FROM_FILE(const char* filename, const char* password) {

            EC_KEY* key_pair = EC_KEY_new();
            BIO* file = BIO_new_file(filename, "rb");
            PEM_read_bio_ECPrivateKey(file, &key_pair, nullptr, (void*)password);
            BIO_free(file);

            return key_pair;
        }

        EC_KEY* EC_PUB_FROM_FILE(const char* filename) {

            EC_KEY* key_pair = EC_KEY_new();
            BIO* file = BIO_new_file(filename, "rb");
            PEM_read_bio_EC_PUBKEY(file, &key_pair, nullptr, nullptr);
            BIO_free(file);

            return key_pair;
        }

        //----// ECDSA
        unsigned char* ECDSA_SIGNATURE(EC_KEY* key_pair, unsigned char* plaintext, int plaintext_length,
            unsigned int* signature_length, VP_HASH::DIGEST_METHOD digest_method,
            unsigned int* return_code) {

            int hash_length = 0;
            unsigned char* hash = VP_HASH::HASH(plaintext, plaintext_length, 1, digest_method);
            int type = 0;

            switch (digest_method)
            {
            case VP_HASH::DIGEST_METHOD::sha1:
                hash_length = SHA_DIGEST_LENGTH;
                type = NID_sha1;
                break;
            case VP_HASH::DIGEST_METHOD::sha256:
                hash_length = SHA256_DIGEST_LENGTH;
                type = NID_sha256;
                break;
            case VP_HASH::DIGEST_METHOD::sha512:
                hash_length = SHA512_DIGEST_LENGTH;
                type = NID_sha512;
                break;
            case VP_HASH::DIGEST_METHOD::sha384:
                hash_length = SHA384_DIGEST_LENGTH;
                type = NID_sha384;
                break;
            case VP_HASH::DIGEST_METHOD::sha224:
                hash_length = SHA224_DIGEST_LENGTH;
                type = NID_sha224;
            default:
                break;
            }

            unsigned char* signature = new unsigned char[2 * hash_length];

            // return 1 on valid, 0 on error

            *return_code = ECDSA_sign(type, hash, hash_length, signature, signature_length, key_pair);

            return signature;
        }

        void ECDSA_VERIFY(EC_KEY* key_pair, unsigned char* plaintext, int plaintext_length, unsigned char* signature,
            unsigned int signature_length, VP_HASH::DIGEST_METHOD digest_method,
            unsigned int* return_code) {

            int hash_length = 0;
            unsigned char* hash = VP_HASH::HASH(plaintext, plaintext_length, 1, digest_method);
            int type = 0;

            switch (digest_method)
            {
            case VP_HASH::DIGEST_METHOD::sha1:
                hash_length = SHA_DIGEST_LENGTH;
                type = NID_sha1;
                break;
            case VP_HASH::DIGEST_METHOD::sha256:
                hash_length = SHA256_DIGEST_LENGTH;
                type = NID_sha256;
                break;
            case VP_HASH::DIGEST_METHOD::sha512:
                hash_length = SHA512_DIGEST_LENGTH;
                type = NID_sha512;
                break;
            case VP_HASH::DIGEST_METHOD::sha384:
                hash_length = SHA384_DIGEST_LENGTH;
                type = NID_sha384;
                break;
            case VP_HASH::DIGEST_METHOD::sha224:
                hash_length = SHA224_DIGEST_LENGTH;
                type = NID_sha224;
            default:
                break;
            }

            // return 1 on valid, 0 on invalid and -1 on error

            *return_code = ECDSA_verify(type, hash, hash_length, signature, (int)signature_length, key_pair);
        }

        //----// ECDH KEY EXCHANGE
        unsigned char* ECDH_KEY_EXCHANGE_EVP(EVP_PKEY* key_pair, EVP_PKEY* peer_key_pair, size_t* shared_key_length) {

            EVP_PKEY_CTX* ctx;
            ctx = EVP_PKEY_CTX_new(key_pair, NULL);

            EVP_PKEY_derive_init(ctx);
            EVP_PKEY_derive_set_peer(ctx, peer_key_pair);

            // get the output length
            EVP_PKEY_derive(ctx, NULL, shared_key_length);
            unsigned char* shared_key = new unsigned char[*shared_key_length];

            EVP_PKEY_derive(ctx, shared_key, shared_key_length);

            return shared_key;
        }

        //----// EC EXAMPLE

        void ec_example() {

            EC_KEY* ecKeys = EC_KEY_GENERATION(NID_secp256k1);
            EVP_PKEY* ecEVPKeys = EC_KEY_GENERATION_EVP(EVP_PKEY_X25519);
            EVP_PKEY* ecEVPKeys2 = EC_KEY_GENERATION_EVP(EVP_PKEY_X25519);

            EC_PRV_TO_FILE(ecKeys, "ec.prv", EVP_aes_128_cbc(), "1234");
            EC_PUB_TO_FILE(ecKeys, "ec.pub");
            ecKeys = EC_PUB_FROM_FILE("ec.pub");
            ecKeys = EC_PRV_FROM_FILE("ec.prv", "1234");

            unsigned int status;
            uchar* plaintext = (uchar*)"Acesta este un test";
            int plaintext_length = 20;

            unsigned int signature_length;
            uchar* signature = ECDSA_SIGNATURE(ecKeys, plaintext, plaintext_length, &signature_length, VP_HASH::DIGEST_METHOD::sha256, &status);
            printf("Sign: %d\n", status);
            printf("Signature: ");
            for (int i = 0; i < signature_length; i++) {
                printf("%c", signature[i]);
            }

            ECDSA_VERIFY(ecKeys, plaintext, plaintext_length, signature, signature_length, VP_HASH::DIGEST_METHOD::sha256, &status);
            printf("\n\nVerify: %d\n", status);

            size_t shared_key_length;
            uchar* shared_key = ECDH_KEY_EXCHANGE_EVP(ecEVPKeys, ecEVPKeys2, &shared_key_length);

            printf("\nShared key: ");
            for (int i = 0; i < shared_key_length; i++) {
                printf("%c", shared_key[i]);
            }
        }
    }

    namespace VP_CERT {

        // X509 CERTIFICATE

        X509* CERTIFICATE_CREATION_WITH_RSA_KEYS(RSA* key_pair, int serial_number, long from, long to,
            const char* country, const char* organization, const char* common_name,
            const EVP_MD* evp_md) {

            X509* cert = X509_new();
            EVP_PKEY* keysign = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(keysign, key_pair);

            ASN1_INTEGER_set(X509_get_serialNumber(cert), serial_number); //serial number
            X509_gmtime_adj(X509_get_notBefore(cert), from); // from
            X509_gmtime_adj(X509_get_notAfter(cert), to);	// to
            X509_set_pubkey(cert, keysign); // public key

            X509_NAME* certName;
            certName = X509_get_subject_name(cert);

            X509_NAME_add_entry_by_txt(certName, "C", MBSTRING_ASC, (unsigned char*)country, -1, -1, 0);
            X509_NAME_add_entry_by_txt(certName, "O", MBSTRING_ASC, (unsigned char*)organization, -1, -1, 0);
            X509_NAME_add_entry_by_txt(certName, "CN", MBSTRING_ASC, (unsigned char*)common_name, -1, -1, 0);

            X509_set_issuer_name(cert, certName);
            X509_sign(cert, keysign, evp_md); // self signed certificate

            return cert;
        }

        X509* CERTIFICATE_CREATION_WITH_EC_KEYS(EC_KEY* key_pair, int serial_number, long from, long to,
            const char* country, const char* organization, const char* common_name,
            const EVP_MD* evp_md) {

            X509* cert = X509_new();
            EVP_PKEY* keysign = EVP_PKEY_new();
            EVP_PKEY_assign_EC_KEY(keysign, key_pair);

            ASN1_INTEGER_set(X509_get_serialNumber(cert), serial_number); //serial number
            X509_gmtime_adj(X509_get_notBefore(cert), from); // from
            X509_gmtime_adj(X509_get_notAfter(cert), to);	// to
            X509_set_pubkey(cert, keysign); // public key

            X509_NAME* certName;
            certName = X509_get_subject_name(cert);

            X509_NAME_add_entry_by_txt(certName, "C", MBSTRING_ASC, (unsigned char*)country, -1, -1, 0);
            X509_NAME_add_entry_by_txt(certName, "O", MBSTRING_ASC, (unsigned char*)organization, -1, -1, 0);
            X509_NAME_add_entry_by_txt(certName, "CN", MBSTRING_ASC, (unsigned char*)common_name, -1, -1, 0);

            X509_set_issuer_name(cert, certName);
            X509_sign(cert, keysign, evp_md); // self signed certificate

            return cert;
        }

        void CERTIFICATE_EXPORT(X509* cert, const char* filename) {

            BIO* file = BIO_new_file(filename, "wb");
            PEM_write_bio_X509(file, cert);
            BIO_free(file);
        }

        void PKCS7_SIGN_DATA(X509* cert, EVP_PKEY* pkey, const char* infile, const char* outfile) {

            // certs stack can be NULL
            // works with either RSA or EC keys

            PKCS7* pkcs = PKCS7_new();
            stack_st_X509* certs = sk_X509_new_reserve(NULL, 1);
            sk_X509_push(certs, cert);

            BIO* file_to_sign;
            file_to_sign = BIO_new_file(infile, "rb");

            pkcs = PKCS7_sign(cert, pkey, certs, file_to_sign, PKCS7_BINARY);
            BIO* outFile = BIO_new_file(outfile, "wb");
            PEM_write_bio_PKCS7(outFile, pkcs);
            BIO_free(file_to_sign);
            BIO_free(outFile);
        }

        void PKCS7_ENCRYPTED_ENVELOPED_DATA(X509* cert, EVP_PKEY* pkey, const char* infile, const char* outfile, 
            const EVP_CIPHER* evp_cipher) {

            // only works with certificates created with RSA keys
            // certs stack can be NULL
            // if evp_cipher is NULL the result is a ENVELOPED DATA structure, otherwise is ENCRYPTED DATA structure

            PKCS7* pkcs = PKCS7_new();
            stack_st_X509* certs = sk_X509_new_reserve(NULL, 1);
            sk_X509_push(certs, cert);

            BIO* file_to_sign;
            file_to_sign = BIO_new_file(infile, "rb");

            pkcs = PKCS7_encrypt(certs, file_to_sign, evp_cipher, PKCS7_BINARY);
            BIO* outFile = BIO_new_file(outfile, "wb");
            PEM_write_bio_PKCS7(outFile, pkcs);
            BIO_free(file_to_sign);
            BIO_free(outFile);
        }

        //----// x509 CERTIFICATE EXAMPLE
        void x509_ceritificate_example() {

            RSA* rsaKeys = VP_RSA::RSA_KEY_GENERATION(2048, 3);
            EVP_PKEY* rsaEVP = VP_UTILS::EVP_PKEY_FROM_RSA_KEY(rsaKeys);
            X509* certRSA = CERTIFICATE_CREATION_WITH_RSA_KEYS(rsaKeys, 1, 0L, 31536000L, "RO", "MTA", "CRYPTO", EVP_sha256());
            CERTIFICATE_EXPORT(certRSA, "certificateRSA.crt");
            PKCS7_SIGN_DATA(certRSA, rsaEVP, "1.txt", "1_pkcs7_rsa.pem");

            EC_KEY* ecKeys = VP_EC::EC_KEY_GENERATION(NID_secp256k1);
            EVP_PKEY* ecEVP = VP_UTILS::EVP_PKEY_FROM_EC_KEY(ecKeys);
            X509* certEC = CERTIFICATE_CREATION_WITH_EC_KEYS(ecKeys, 1, 0L, 31536000L, "RO", "MTA", "CRYPTO", EVP_sha256());
            CERTIFICATE_EXPORT(certEC, "certificateEC.crt");
            PKCS7_SIGN_DATA(certEC, ecEVP, "1.txt", "1_pkcs7_ec.pem");
        }
    }

    namespace VP_UTILS {

        // UTILS

        EVP_PKEY* EVP_PKEY_FROM_RSA_KEY(RSA* key) {

            EVP_PKEY* tmp = EVP_PKEY_new();
            EVP_PKEY_set1_RSA(tmp, key);

            return tmp;
        }

        EVP_PKEY* EVP_PKEY_FROM_EC_KEY(EC_KEY* key) {

            EVP_PKEY* tmp = EVP_PKEY_new();
            EVP_PKEY_set1_EC_KEY(tmp, key);

            return tmp;
        }

        unsigned char* HEX_TO_BIN(unsigned char* hex) {

            unsigned char* bin = new unsigned char[8];
            BIGNUM* bn = BN_new();
            BN_hex2bn(&bn, (const char*)hex);
            BN_bn2bin(bn, bin);

            return bin;
        }

        unsigned char* GEN_PBKDF1(const char* password, const char* salt, long iter) {

            unsigned char* dk = new unsigned char[SHA_DIGEST_LENGTH];
            size_t pwlen = strlen(password);
            size_t dlen = pwlen + 8;
            unsigned char* buf;

            if (dlen > SHA_DIGEST_LENGTH)
                buf = (unsigned char*)malloc(dlen);
            else
                buf = (unsigned char*)malloc(SHA_DIGEST_LENGTH);

            memcpy(buf, password, pwlen);
            strncpy((char*)buf + pwlen, salt, 8);

            while (iter-- > 0) {
                SHA1(buf, dlen, buf);
                dlen = SHA_DIGEST_LENGTH;
            }

            memcpy(dk, buf, SHA_DIGEST_LENGTH);

            return dk;
        }

        unsigned char* GEN_PBKDF2(const char* password, int password_length, const unsigned char* salt,
            int salt_length, int iter_cnt, int out_length) {

            unsigned char* output = new unsigned char[out_length];
            PKCS5_PBKDF2_HMAC(password, password_length, salt, salt_length, iter_cnt, EVP_sha256(), out_length, output);

            return output;
        }

        int GET_FILE_LENGTH(const char* filename) {

            FILE* file = fopen(filename, "rb");
            fseek(file, 0L, SEEK_END);
            int len = ftell(file);
            fclose(file);

            return len;
        }

        unsigned char* GET_FILE_CONTENT(const char* filename, int file_length) {

            FILE* file = fopen(filename, "rb");
            unsigned char* content = new unsigned char[file_length];
            fread(content, file_length, 1, file);
            fclose(file);

            return content;
        }

        void PRINT_HEX(unsigned char* buffer, int length) {

            for (int i = 0; i < length; ++i)
                printf("%02X ", buffer[i]);
        }

        unsigned char* READ_TEXT_FROM_KEYBOARD(int* length) {

            char tmp_text[1024];
            fgets(tmp_text, sizeof(tmp_text), stdin);
            *length = strlen(tmp_text) - 1;
            unsigned char* text = new unsigned char[*length];
            memcpy((char*)text, tmp_text, *length);
            text[*length] = '\0';

            return text;
        }

        //----// UTILS EXAMPLE
        void utils_example() {

            uchar* key = (uchar*)"85c60c716f29fbb60498b83b6e55f771";
            uchar* iv = (uchar*)"ffa111f76d4b95ee96e15bca9fe07a49";

            uchar* new_key = HEX_TO_BIN(key);
            uchar* new_iv = HEX_TO_BIN(iv);

            uchar* salt = new uchar[16];
            RAND_bytes(salt, 16);
            uchar* pbkdf2 = GEN_PBKDF2("1234", 4, salt, 16, 10, 16);
        }
    }
}