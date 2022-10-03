#include <sqlite3.h>
#include "pp_api.hpp"
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

#define NONCE_SIZE 16

int pps_count = 0;
bool pp_is_ok = false;
int pp_id = -1;
bool node_is_ok = false;
bool challenge_is_ok = false;
int node_id = -1;
nl::json node_data_json;

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

static int get_pp_from_db_callback(void *pps_json, int count, char **data, char **columns)
{
    std::string json_name = "platform_provider_";
    nl::json pp_json;
    nl::json *pps_json_ptr = reinterpret_cast<nl::json *>(pps_json);
    pps_count++;

    for (int idx = 0; idx < count; idx++)
    {

        if (!strcmp(columns[idx], "id"))
        {
            pp_json["id"] = (data[idx] == nullptr) ? "" : (std::string)data[idx];
        }
        else if (!strcmp(columns[idx], "pub_key"))
        {
            pp_json["pub_key"] = (data[idx] == nullptr) ? "" : (std::string)data[idx];
        }
    }

    (*pps_json_ptr)[json_name + std::to_string(pps_count)] = pp_json;

    return 0;
}

nl::json get_pp_from_db()
{
    nl::json pps_json;
    pps_count = 0;
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, "SELECT * FROM platform_providers", get_pp_from_db_callback, &pps_json, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }

    sqlite3_close(db);

    if (!pps_count)
    {
        pps_json["Message"] = "No platform providers";
        return pps_json;
    }

    return pps_json;
}

static int check_pp_pub_key_callback(void *param, int count, char **data, char **columns)
{
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "TOT"))
        {
            pp_is_ok = (atoi(data[idx]) == 1) ? true : false;
        }
        else if (!strcmp(columns[idx], "id"))
        {
            pp_id = (data[idx] == nullptr) ? -1 : atoi(data[idx]);
        }
    }

    return 0;
}

bool check_pp_pub_key(std::string pp_pub_key)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql = "SELECT COUNT(*) as TOT, id FROM platform_providers WHERE pub_key='" + pp_pub_key + "'";
    pp_is_ok = false;
    pp_id = -1;

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), check_pp_pub_key_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    return pp_is_ok;
}

static int check_node_callback(void *param, int count, char **data, char **columns)
{
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "status"))
        {
            node_is_ok = (data[idx] == nullptr) ? true : (strcmp(data[idx], "active"));
        }
    }

    return 0;
}

bool check_node(nl::json node_data)
{
    if (!node_data.contains("uuid") || !node_data.contains("sm_hash") || !node_data.contains("ip") || !node_data.contains("port") || !node_data.contains("dev_pub_key"))
    {
        fprintf(stderr, "Wrong Data Received\n");
        return false;
    }

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql = "SELECT id, status FROM nodes WHERE uuid='" + node_data["uuid"].get<std::string>() + "'";
    node_is_ok = true;

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), check_node_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    return node_is_ok;
}

bool save_node_db(nl::json node_data, unsigned char *challenge)
{

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    time_t timer = time(NULL);
    char timestamp[26];
    struct tm *tm_info = localtime(&timer);

    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    std::string uuid = node_data["uuid"].get<std::string>();
    std::string sm_hash = node_data["sm_hash"].get<std::string>();
    std::string ip = node_data["ip"].get<std::string>();
    std::string port = node_data["port"].get<std::string>();
    std::string dev_pub_key = node_data["dev_pub_key"].get<std::string>();
    char *challenge_base64;
    size_t challenge_size = Base64Encode(reinterpret_cast<const char *>(challenge), &challenge_base64, NONCE_SIZE);

    if (!challenge_size)
    {
        fprintf(stderr, "Can't encode challenge\n");
        return false;
    }

    std::string challenge_64_str(challenge_base64, challenge_size);
    std::string sql = "INSERT INTO nodes(pp_id, uuid, sm_hash, ip, port, status, timestamp, challenge, dev_pub_key) VALUES(" + std::to_string(pp_id) + ", '" + uuid + "', '" + sm_hash + "', '" + ip + "', " + port + ", 'not active', '" + std::string(timestamp) + "', '" + challenge_64_str + "', '" + dev_pub_key + "') ON CONFLICT(uuid) DO UPDATE SET pp_id =" + std::to_string(pp_id) + ",uuid ='" + uuid + "', sm_hash ='" + sm_hash + "', ip ='" + ip + "', port =" + port + ", status ='not active', timestamp = '" + std::string(timestamp) + "', challenge='" + challenge_64_str + "', dev_pub_key='" + dev_pub_key + "'";

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), 0, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    return true;
}

bool generate_pp_challenge(unsigned char *challenge)
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

nl::json check_pp_send_challenge(nl::json data_json)
{
    nl::json response_json;
    unsigned char challenge[256] = {'\0'};
    if (!data_json.contains("pp_pub_key") || !check_pp_pub_key(data_json["pp_pub_key"]) || !check_node(data_json))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }

    if (!generate_pp_challenge(challenge) || !save_node_db(data_json, challenge) || !encrypt_challenge(challenge, data_json["pp_pub_key"]))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }

    response_json["challenge"] = std::string((char *)challenge);
    return response_json;
}

static int check_challenge_callback(void *param, int count, char **data, char **columns)
{
    challenge_is_ok = true;
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "id"))
        {
            node_id = (data[idx] == nullptr) ? -1 : atoi(data[idx]);
        }
        else if (!strcmp(columns[idx], "uuid"))
        {
            node_data_json["uuid"] = std::string(data[idx]);
        }
        else if (!strcmp(columns[idx], "sm_hash"))
        {
            node_data_json["sm_hash"] = std::string(data[idx]);
        }
        else if (!strcmp(columns[idx], "ip"))
        {
            node_data_json["ip"] = std::string(data[idx]);
        }
        else if (!strcmp(columns[idx], "port"))
        {
            node_data_json["port"] = std::string(data[idx]);
        }
        else if (!strcmp(columns[idx], "dev_pub_key"))
        {
            node_data_json["dev_pub_key"] = std::string(data[idx]);
        }
    }

    return 0;
}

bool check_challenge(std::string challenge)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql = "SELECT id, uuid, sm_hash, ip, port, dev_pub_key FROM nodes WHERE challenge='" + challenge + "' AND status = 'not active'";
    challenge_is_ok = false;
    node_id = -1;
    node_data_json = {};

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), check_challenge_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    return challenge_is_ok;
}

bool send_values_to_verifier()
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
        curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1:6000/node_register");

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
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, node_data_json.dump().length());
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, node_data_json.dump().c_str());

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

void update_node_status(){
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    time_t timer = time(NULL);
    char timestamp[26];
    struct tm *tm_info = localtime(&timer);

    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    std::string sql = "UPDATE nodes SET status='active', timestamp='" + std::string(timestamp) + "' WHERE id=" + std::to_string(node_id); 

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return;
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return;
    }

    sqlite3_close(db);
 
    return;

}

nl::json accept_node_db(nl::json data_json)
{
    if (!data_json.contains("challenge") || !check_challenge(data_json["challenge"]) || !send_values_to_verifier())
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }
    else
    {
        update_node_status();
        return {{"Message", "Node Correctly Registered"}, {"Code", "200"}};
    }
}
