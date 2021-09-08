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

        void INCREMENT_COUNTER(unsigned char* counter, int position);

        void ADD_PADDING(unsigned char** data, int& dataLen, int blockSize);

        void REMOVE_PADDING(unsigned char** data, int& dataLen, int blockSize);

        void GENERATE_SALT(int passLength, unsigned char** salt, int& saltLength);

        //----// AES-ECB
        void AES_ENC_ECB(unsigned char** pData, int& dataLen, unsigned char* userkey,
            unsigned char** encData);

        void AES_DEC_ECB(unsigned char** encData, int& dataLen, unsigned char* userkey,
            unsigned char** decData);

        //----// AES_CTR
        void AES_ENC_CTR(unsigned char** pData, int& dataLen, unsigned char* counter,
            unsigned char* userkey, unsigned char** encData);

        void AES_DEC_CTR(unsigned char** encData, int& dataLen, unsigned char* counter,
            unsigned char* userkey, unsigned char** decData);

        //----// AES_CBC
        void AES_ENC_CBC(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** encData);

        void AES_DEC_CBC(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** decData);

        //----// AES_OFB
        void AES_ENC_OFB(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** encData);

        void AES_DEC_OFB(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** decData);

        //----// AES_CFB
        void AES_ENC_CFB(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** encData);

        void AES_DEC_CFB(unsigned char** encData, int& dataLen, unsigned char* iv, unsigned char* userkey,
            unsigned char** decData);

        //----// RC4
        void RC4_ENC(unsigned char** inputData, int& inputDataLen, unsigned char* key, unsigned char** encData);

        void RC4_DEC(unsigned char** encData, int& encDataLen, unsigned char* key, unsigned char** decData);

        //----// EXAMPLE
        void aes_example();
    }

    namespace VP_AES_EVP {
        // AES EVP

        unsigned char* AES_ENC_EVP(unsigned char* plaintext, int plaintext_length, unsigned char* key,
            unsigned char* iv, int* ciphertext_length, const EVP_CIPHER* evp_chiper);

        unsigned char* AES_DEC_EVP(unsigned char* ciphertext, int ciphertext_length, unsigned char* key,
            unsigned char* iv, int* plaintext_length, const EVP_CIPHER* evp_cipher);

        //----// AES EVP EXAMPLE
        void aes_evp_example();
    }

    namespace VP_HASH {
        // HASH

        enum class DIGEST_METHOD {
            sha1 = 0,
            sha256 = 1,
            sha512 = 2,
            sha384 = 3,
            sha224 = 4
        };

        unsigned char* HASH(unsigned char* plaintext, int plaintext_length, int iter,
            VP_HASH::DIGEST_METHOD digest_method);

        unsigned char* HASH_EVP(unsigned char* plaintext, int plaintext_length, int iter,
            const EVP_MD* evp_digest_method, unsigned int* digest_length);

        //----// HASH EXAMPLE
        void hash_example();
    }

    namespace VP_RSA {

        // RSA 

        enum class PADDING {
            RSA_PKCS1 = 1,
            RSA_NO = 3,
            RSA_PKCS1_OAEP = 4
        };

        RSA* RSA_KEY_GENERATION(int bits, int exponent);

        unsigned char* RSA_ENCRYPTION(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            PADDING padding, unsigned int* return_code);

        unsigned char* RSA_DECRYPTION(RSA* rsa_handler, unsigned char* ciphertext,
            PADDING padding, unsigned int* return_code);

        unsigned char* RSA_SIGN_USING_ENCRYPT(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            VP_HASH::DIGEST_METHOD digest_method, PADDING padding, unsigned int* return_code);

        void RSA_VERIFY_USING_DECRYPT(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            unsigned char* signature, VP_HASH::DIGEST_METHOD digest_method, PADDING padding,
            unsigned int* return_code);

        unsigned char* RSA_SIGN(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length,
            VP_HASH::DIGEST_METHOD digest_method, unsigned int* signature_length,
            unsigned int* return_code);

        void RSA_VERIFY(RSA* rsa_handler, unsigned char* plaintext, int plaintext_length, unsigned char* signature,
            unsigned int signature_length, VP_HASH::DIGEST_METHOD digest_method, unsigned int* return_code);

        //----// RSA TO FILE - PKCS1
        void RSA_PUB_PKCS1_TO_FILE(RSA* rsa_handler, const char* filename);

        void RSA_PRV_PKCS1_TO_FILE(RSA* rsa_handler, const char* filename, const EVP_CIPHER* evp_cipher,
            const char* password);

        //----// RSA TO FILE - PKCS8
        void RSA_PUB_PKCS8_TO_FILE(RSA* rsa_handler, const char* filename);

        void RSA_PRV_PKCS8_TO_FILE(RSA* rsa_handler, const char* filename, const EVP_CIPHER* evp_cipher,
            const char* password);

        //----// RSA FROM FILE - PKCS1
        RSA* RSA_PRV_PKCS1_FROM_FILE(const char* filename, const char* password);

        //----// RSA FROM FILE - PKCS8
        RSA* RSA_PRV_PKCS8_FROM_FILE(const char* filename, const char* password);

        //----// RSA UTILS

        BIGNUM* BN_GET_NEXT_PRIME(int start_point);

        BIGNUM* BN_GET_PRIME(int start_point);

        int GET_NEXT_PRIME(int start_point);

        int GET_PRIME(int start_point);

        void RSA_PRINT_CONTENTS(RSA* rsa_handler);

        //----// RSA EXAMPLE

        void rsa_example();
    }

    namespace VP_EC {
        // EC

        EC_KEY* EC_KEY_GENERATION(int curve_id);

        EVP_PKEY* EC_KEY_GENERATION_EVP(int evp_curve_id);

        //----// EC TO FILE
        void EC_PRV_TO_FILE(EC_KEY* key_pair, const char* filename, const EVP_CIPHER* evp_cipher,
            const char* password);

        void EC_PUB_TO_FILE(EC_KEY* key_pair, const char* filename);

        //----// EC FROM FILE
        EC_KEY* EC_PRV_FROM_FILE(const char* filename, const char* password);

        EC_KEY* EC_PUB_FROM_FILE(const char* filename);

        //----// ECDSA
        unsigned char* ECDSA_SIGNATURE(EC_KEY* key_pair, unsigned char* plaintext, int plaintext_length,
            unsigned int* signature_length, VP_HASH::DIGEST_METHOD digest_method,
            unsigned int* return_code);

        void ECDSA_VERIFY(EC_KEY* key_pair, unsigned char* plaintext, int plaintext_length, unsigned char* signature,
            unsigned int signature_length, VP_HASH::DIGEST_METHOD digest_method,
            unsigned int* return_code);

        //----// ECDH KEY EXCHANGE
        unsigned char* ECDH_KEY_EXCHANGE_EVP(EVP_PKEY* key_pair, EVP_PKEY* peer_key_pair, size_t* shared_key_length);

        //----// EC EXAMPLE

        void ec_example();
    }

    namespace VP_CERT {

        // X509 CERTIFICATE

        X509* CERTIFICATE_CREATION_WITH_RSA_KEYS(RSA* key_pair, int serial_number, long from, long to,
            const char* country, const char* organization, const char* common_name,
            const EVP_MD* evp_md);

        X509* CERTIFICATE_CREATION_WITH_EC_KEYS(EC_KEY* key_pair, int serial_number, long from, long to,
            const char* country, const char* organization, const char* common_name,
            const EVP_MD* evp_md);

        void CERTIFICATE_EXPORT(X509* cert, const char* filename);

        void PKCS7_SIGN_DATA(X509* cert, EVP_PKEY* pkey, const char* infile, const char* outfile);

        //----// x509 CERTIFICATE EXAMPLE
        void x509_ceritificate_example();
    }

    namespace VP_UTILS {

        // UTILS

        EVP_PKEY* EVP_PKEY_FROM_RSA_KEY(RSA* key);

        EVP_PKEY* EVP_PKEY_FROM_EC_KEY(EC_KEY* key);

        unsigned char* HEX_TO_BIN(unsigned char* hex);

        unsigned char* GEN_PBKDF1(const char* password, const char* salt, long iter);

        unsigned char* GEN_PBKDF2(const char* password, int password_length, const unsigned char* salt,
            int salt_length, int iter_cnt, int out_length);

        int GET_FILE_LENGTH(const char* filename);

        unsigned char* GET_FILE_CONTENT(const char* filename, int file_length);

        void PRINT_HEX(unsigned char* buffer, int length);

        unsigned char* READ_TEXT_FROM_KEYBOARD(int* length);

        //----// UTILS EXAMPLE
        void utils_example();
    }
}