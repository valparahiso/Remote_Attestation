#include "openssl_op.hpp"
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <time.h>
#include <iostream>
#include <curl/curl.h>
#include <cstring>

#define NONCE_SIZE 16

int calcDecodeLength(const char *b64input)
{ // Calculates the length of a decoded base64 string
    int len = strlen(b64input);
    int padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') // last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') // last char is =
        padding = 1;

    return (int)len * 0.75 - padding;
}

size_t Base64Encode(const char *buffer, char **b64text, size_t buffer_size)
{ // Encodes a binary safe base 64 string
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    if(buffer_size == 0)
        buffer_size = NONCE_SIZE;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines - write everything in one line
    BIO_write(bio, buffer, buffer_size);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *b64text = bufferPtr->data;

    return bufferPtr->length; // success
}

int Base64Decode(char *b64message, char **buffer)
{ // Decodes a base64 encoded string
    BIO *bio, *b64;
    int decodeLen = calcDecodeLength(b64message),
        len = 0;
    *buffer = (char *)malloc(decodeLen + 1);
    FILE *stream = fmemopen(b64message, strlen(b64message), "r");

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer
    len = BIO_read(bio, *buffer, strlen(b64message));
    // Can test here if len == decodeLen - if not, then return an error
    (*buffer)[len] = '\0';

    BIO_free_all(bio);
    fclose(stream);

    return (0); // success
}

bool generate_challenge(unsigned char *challenge)
{
    unsigned char nonce[NONCE_SIZE];
    int rc = RAND_bytes(nonce, NONCE_SIZE);

    if (rc != 1)
    {
        fprintf(stderr, "Can't generate challenge\n");
        return false;
    }

    memcpy(challenge, nonce, NONCE_SIZE);
    return true;
}

int EVP_PKEY_get_type(EVP_PKEY *pkey)
{
    if (!pkey)
        return EVP_PKEY_NONE;

    return EVP_PKEY_type(EVP_PKEY_id(pkey));
}

std::string format_RSA_pub_key(std::string key)
{
    std::string RSA_key = "-----BEGIN PUBLIC KEY-----\n";

    for (int i = 1; i <= (int)key.length(); i++)
    {

        RSA_key += key[i - 1];
        if (i % 64 == 0)
            RSA_key += "\n";
    }

    RSA_key += "\n-----END PUBLIC KEY-----\n";

    return RSA_key;
}

std::string getOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    std::string ret(buf, len);
    BIO_free(bio);
    return ret;
}

bool encrypt_challenge(unsigned char *challenge, std::string pp_pub_key)
{
    std::string pem_key = format_RSA_pub_key(pp_pub_key);
    const unsigned char *key = reinterpret_cast<const unsigned char *>(pem_key.c_str());

    BIO *bio = BIO_new_mem_buf(key, std::string(reinterpret_cast<const char *>(key)).length());
    if (bio == nullptr)
        return false;

    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (pkey == nullptr)
        return false;

    int type = EVP_PKEY_get_type(pkey);
    if (type != EVP_PKEY_RSA && type != EVP_PKEY_RSA2)
        return false;

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == nullptr)
        return false;

    char *challenge_base64;
    unsigned char encrypted_data[RSA_size(rsa)];

    if ((RSA_public_encrypt(NONCE_SIZE, challenge, encrypted_data, rsa, RSA_PKCS1_OAEP_PADDING)) == -1)
        return false;

    size_t encrypted_size = Base64Encode(reinterpret_cast<char *>(encrypted_data), &challenge_base64, sizeof(encrypted_data));

    if (!encrypted_size)
        return false;

    memcpy(challenge, challenge_base64, encrypted_size);

    EVP_PKEY_free(pkey);
    RSA_free(rsa);
    BIO_free(bio);

    return true;
}

bool send_values_to_verifier(std::string url, nl::json data)
{
    long http_code = 0;
    CURL *curl;
    CURLcode res;
    curl_slist *hs = nullptr;
    hs = curl_slist_append(hs, "Content-Type: application/json");

    static const char *pCertFile = "../certs/registrar/registrar.crt";
    static const char *pCACertFile = "../certs/CA/CA.crt";
    static const char *pKeyName = "../certs/registrar/registrar.key";

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

        // curl_easy_setopt(curl, CURLOPT_HEADERDATA, headerfile);
        curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");

        // Client authN
        curl_easy_setopt(curl, CURLOPT_SSLCERT, pCertFile);
        curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
        curl_easy_setopt(curl, CURLOPT_SSLKEY, pKeyName);

        // CA
        curl_easy_setopt(curl, CURLOPT_CAINFO, pCACertFile);

        // Server AuthN
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

        // Values of DB as data
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.dump().length());
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, data.dump().c_str());

        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        res = curl_easy_perform(curl);

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl);
            return false;
        }
        else
        {
            curl_easy_cleanup(curl);
            return (http_code == 200);
        }
    }
    else
    {
        curl_global_cleanup();
        return false;
    }
}