#include "registration.hpp"
#include <iostream>

int attestor_id = -1;
int eapp_id = -1;
std::string sm_hash = "NONE";

bool insert_attester_db(nl::json attester_data)
{
    if (!attester_data.contains("dev_pub_key") || !attester_data.contains("ip") || !attester_data.contains("port") || !attester_data.contains("uuid"))
        return false;

    std::string uuid = attester_data["uuid"].get<std::string>();
    std::string ip = attester_data["ip"].get<std::string>();
    std::string port = attester_data["port"].get<std::string>();
    std::string dev_pub_key = attester_data["dev_pub_key"].get<std::string>();

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql;

    /* Open database */
    rc = sqlite3_open("./db/gvalues.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    sql = "INSERT OR IGNORE INTO attestors(uuid, pubkey, hostname, port) VALUES ('" + uuid + "', '" + dev_pub_key + "', '" + ip + "', '" + port + "')";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return false;
    }

    sqlite3_close(db);
    return true;
}

bool insert_sm_gvalues_db(nl::json attester_data)
{
    if (!attester_data.contains("sm_hash") || !attester_data.contains("uuid"))
        return false;

    std::string uuid = attester_data["uuid"].get<std::string>();
    std::string sm_hash = attester_data["sm_hash"].get<std::string>();

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql;

    /* Open database */
    rc = sqlite3_open("./db/gvalues.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    sql = "INSERT INTO gvalues(attestor, enclave_hash, sm_hash, eapp, eapp_and_attestor) SELECT attestors.id, 'NONE', '" + sm_hash + "', -1, attestors.id FROM attestors WHERE attestors.uuid = '" + uuid + "'";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return false;
    }

    sqlite3_close(db);
    return true;
}

nl::json register_node_db(nl::json attester_data)
{
    if (!insert_attester_db(attester_data) || !insert_sm_gvalues_db(attester_data))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }
    else
        return {{"Message", "Node Correctly Registered"}, {"Code", "200"}};
}

static int get_attester_id_callback(void *notUsed, int count, char **data, char **columns)
{
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "id"))
        {
            attestor_id = atoi(data[idx]);
        }
    }

    return 0;
}

static int get_sm_hash_callback(void *notUsed, int count, char **data, char **columns)
{
    for (int idx = 0; idx < count; idx++)
    {
        if (!strcmp(columns[idx], "sm_hash"))
        {
            sm_hash = std::string(data[idx]);
        }
        else if (!strcmp(columns[idx], "eapp_id"))
        {
            eapp_id = atoi(data[idx]);
        }
    }

    return 0;
}

bool insert_eapp_db(nl::json eapp_data)
{
    if (!eapp_data.contains("uuid") || !eapp_data.contains("eapp_path"))
        return false;

    std::string uuid = eapp_data["uuid"].get<std::string>();
    std::string eapp_path = eapp_data["eapp_path"].get<std::string>();

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql;
    attestor_id = -1;

    /* Open database */
    rc = sqlite3_open("./db/gvalues.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    sql = "SELECT id FROM attestors WHERE uuid = '" + uuid + "'";
    std::cout << sql << std::endl;

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), get_attester_id_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return false;
    }

    if (attestor_id == -1)
        return false;

    sql = "INSERT OR IGNORE INTO eapps(attestor, path, path_and_attestor) VALUES (" + std::to_string(attestor_id) + ", '" + eapp_path + "','" + eapp_path + std::to_string(attestor_id) + "')";
    std::cout << sql << std::endl;

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return false;
    }

    sqlite3_close(db);
    return true;
}

bool insert_eapp_gvalues_db(nl::json eapp_data)
{
    if (!eapp_data.contains("eapp_hash") || !eapp_data.contains("eapp_path"))
        return false;

    std::string eapp_hash = eapp_data["eapp_hash"].get<std::string>();
    std::string eapp_path = eapp_data["eapp_path"].get<std::string>();

    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    std::string sql;
    eapp_id = -1;
    sm_hash = "NONE";
    /* Open database */
    rc = sqlite3_open("./db/gvalues.db", &db);

    if (rc)
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return false;
    }

    sql = "SELECT G.sm_hash AS sm_hash, E.id as eapp_id FROM gvalues AS G, eapps AS E WHERE G.attestor=" + std::to_string(attestor_id) + " AND G.enclave_hash='NONE' AND G.eapp=-1 AND E.path_and_attestor = '" + eapp_path + std::to_string(attestor_id) + "'";
    std::cout << sql << std::endl;

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql.c_str(), get_sm_hash_callback, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return false;
    }

    if (sm_hash.empty() || !sm_hash.compare("NONE") || eapp_id == -1)
    {
        return false;
    }

    sql = "INSERT OR IGNORE INTO gvalues (attestor, enclave_hash, sm_hash, eapp, eapp_and_attestor) VALUES (" + std::to_string(attestor_id) + ", '" + eapp_hash + "', '" + sm_hash + "', " + std::to_string(eapp_id) + ", " + std::to_string(eapp_id) + std::to_string(attestor_id) + ")";
    std::cout << sql << std::endl;
    rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &zErrMsg);

    if (rc != SQLITE_OK)
    {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return false;
    }

    sqlite3_close(db);
    return true;
}

nl::json register_eapp_db(nl::json attester_data)
{
    if (!insert_eapp_db(attester_data) || !insert_eapp_gvalues_db(attester_data))
    {
        return {{"Error", "Internal Server Error"}, {"Code", "500"}};
    }
    else
        return {{"Message", "Eapp Correctly Registered"}, {"Code", "200"}};
}