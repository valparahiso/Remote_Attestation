#include <sqlite3.h>
#include "pp_api.hpp"
#include <time.h>
#include <iostream>
#include <curl/curl.h>
#include "openssl_op.hpp"

int pps_count = 0;
bool pp_is_ok = false;
int pp_id = -1;
bool node_is_ok = false;
bool challenge_pp_is_ok = false;
int node_id = -1;
nl::json node_data_json;

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
    size_t challenge_size = Base64Encode(reinterpret_cast<const char *>(challenge), &challenge_base64, 0);

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

nl::json check_pp_send_challenge(nl::json data_json)
{
    nl::json response_json;
    unsigned char challenge[256] = {'\0'};
    if (!data_json.contains("pp_pub_key") || !check_pp_pub_key(data_json["pp_pub_key"]) || !check_node(data_json))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }

    if (!generate_challenge(challenge) || !save_node_db(data_json, challenge) || !encrypt_challenge(challenge, data_json["pp_pub_key"]))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }

    response_json["challenge"] = std::string((char *)challenge);
    return response_json;
}

static int check_challenge_callback(void *param, int count, char **data, char **columns)
{
    challenge_pp_is_ok = true;
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

bool check_pp_challenge(std::string challenge)
{
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql = "SELECT id, uuid, sm_hash, ip, port, dev_pub_key FROM nodes WHERE challenge='" + challenge + "' AND status = 'not active'";
    challenge_pp_is_ok = false;
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

    return challenge_pp_is_ok;
}

void update_node_status()
{
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
    if (!data_json.contains("challenge") || !check_pp_challenge(data_json["challenge"]) || !send_values_to_verifier("https://127.0.0.1:6000/node_register", node_data_json))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }
    else
    {
        update_node_status();
        return {{"Message", "Node Correctly Registered"}, {"Code", "200"}};
    }
}
