#include <sqlite3.h>
#include "developer_api.hpp"
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

bool developer_is_ok = false;
int developer_id = -1;
bool eapp_is_ok = false;
bool challenge_developer_is_ok = false;
int eapp_id = -1;
nl::json eapp_data_json;

static int check_developer_pub_key_callback(void *param, int count, char **data, char **columns)
{
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "TOT"))
        {
            developer_is_ok = (atoi(data[idx]) == 1) ? true : false;
        }
        else if (!strcmp(columns[idx], "id"))
        {
            developer_id = (data[idx] == nullptr) ? -1 : atoi(data[idx]);
        }
    }

    return 0;
}

bool check_developer_pub_key(std::string developer_pub_key)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql = "SELECT COUNT(*) as TOT, id FROM developers WHERE pub_key='" + developer_pub_key + "'";
    developer_is_ok = false;
    developer_id = -1;

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), check_developer_pub_key_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    return developer_is_ok;
}

static int check_eapp_callback(void *param, int count, char **data, char **columns)
{
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "node_status"))
        {
            eapp_is_ok = (data[idx] == nullptr) ? eapp_is_ok : ((!strcmp(data[idx], "active") || eapp_is_ok));
        }
        else if (!strcmp(columns[idx], "eapp_status"))
        {
            eapp_is_ok = (data[idx] == nullptr) ? eapp_is_ok : ((strcmp(data[idx], "active") || eapp_is_ok));
        }
    }

    return 0;
}

bool check_eapp(nl::json eapp_data)
{
    if (!eapp_data.contains("uuid") || !eapp_data.contains("eapp_hash") || !eapp_data.contains("eapp_path"))
    {
        fprintf(stderr, "Wrong Data Received\n");
        return false;
    }

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql = "SELECT status AS eapp_status FROM eapps WHERE uuid_and_hash='" + eapp_data["uuid"].get<std::string>() + eapp_data["eapp_hash"].get<std::string>() + "'";
    eapp_is_ok = true;

    /* Open database */
    rc = sqlite3_open("./db/registrar.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), check_eapp_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return false;
    }

    sql = "SELECT status AS node_status FROM nodes WHERE uuid ='" + eapp_data["uuid"].get<std::string>() + "'";

    rc = sqlite3_exec(db, sql.c_str(), check_eapp_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return false;
    }

    sqlite3_close(db);

    return eapp_is_ok;
}

bool save_eapp_db(nl::json eapp_data, unsigned char *challenge)
{

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    time_t timer = time(NULL);
    char timestamp[26];
    struct tm *tm_info = localtime(&timer);

    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);

    std::string uuid = eapp_data["uuid"].get<std::string>();
    std::string eapp_hash = eapp_data["eapp_hash"].get<std::string>();
    std::string eapp_path = eapp_data["eapp_path"].get<std::string>();

    char *challenge_base64;
    size_t challenge_size = Base64Encode(reinterpret_cast<const char *>(challenge), &challenge_base64, 0);

    if (!challenge_size)
    {
        fprintf(stderr, "Can't encode challenge\n");
        return false;
    }

    std::string challenge_64_str(challenge_base64, challenge_size);
    // TODO rendere unico l'onconflict
    std::string sql = "INSERT INTO eapps(developer_id, node_uuid, eapp_hash, eapp_path, status, timestamp, challenge, uuid_and_hash) VALUES(" + std::to_string(developer_id) + ", '" + uuid + "', '" + eapp_hash + "', '" + eapp_path + "', 'not active', '" + std::string(timestamp) + "', '" + challenge_64_str + "', '" + uuid + eapp_hash + "') ON CONFLICT(uuid_and_hash) DO UPDATE SET developer_id =" + std::to_string(developer_id) + ",node_uuid ='" + uuid + "', eapp_hash ='" + eapp_hash + "', status ='not active', timestamp = '" + std::string(timestamp) + "', challenge='" + challenge_64_str + "', uuid_and_hash='" + uuid + eapp_hash + "'";

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

nl::json check_developer_send_challenge(nl::json data_json)
{
    nl::json response_json;
    unsigned char challenge[256] = {'\0'};
    if (!data_json.contains("developer_pub_key") || !check_developer_pub_key(data_json["developer_pub_key"]) || !check_eapp(data_json))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }

    if (!generate_challenge(challenge) || !save_eapp_db(data_json, challenge) || !encrypt_challenge(challenge, data_json["developer_pub_key"]))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "300"}};
    }

    response_json["challenge"] = std::string((char *)challenge);
    return response_json;
}

static int check_challenge_callback(void *param, int count, char **data, char **columns)
{
    challenge_developer_is_ok = true;
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "id"))
        {
            eapp_id = (data[idx] == nullptr) ? -1 : atoi(data[idx]);
        }
        else if (!strcmp(columns[idx], "node_uuid"))
        {
            eapp_data_json["uuid"] = std::string(data[idx]);
        }
        else if (!strcmp(columns[idx], "eapp_hash"))
        {
            eapp_data_json["eapp_hash"] = std::string(data[idx]);
        }
        else if (!strcmp(columns[idx], "eapp_path"))
        {
            eapp_data_json["eapp_path"] = std::string(data[idx]);
        }
    }

    return 0;
}

bool check_developer_challenge(std::string challenge)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql = "SELECT id, node_uuid, eapp_hash, eapp_path FROM eapps WHERE challenge='" + challenge + "' AND status = 'not active'";
    challenge_developer_is_ok = false;
    eapp_id = -1;
    eapp_data_json = {};

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

    return challenge_developer_is_ok;
}

void update_eapp_status()
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    time_t timer = time(NULL);
    char timestamp[26];
    struct tm *tm_info = localtime(&timer);

    strftime(timestamp, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    std::string sql = "UPDATE eapps SET status='active', timestamp='" + std::string(timestamp) + "' WHERE id=" + std::to_string(eapp_id);

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

nl::json accept_eapp_db(nl::json data_json)
{
    if (!data_json.contains("challenge") || !check_developer_challenge(data_json["challenge"]) || !send_values_to_verifier("https://127.0.0.1:6000/eapp_register", eapp_data_json))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }
    else
    {
        update_eapp_status();
        return {{"Message", "Node Correctly Registered"}, {"Code", "200"}};
    }
}
