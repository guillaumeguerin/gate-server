#ifndef DATABASE_H
#define DATABASE_H

#include <mysql++.h>

class Database
{
private:
    Database();

public:
    ~Database();

public:
    static Database* GetPtr();
    static Database& Get();

public:
    bool                        Initalize(const char* database, const char *serverAddress, const char *username, const char *password, unsigned int port);
    mysqlpp::StoreQueryResult   RunQuery(const char* runQuery);

private:
    static Database* g_Instance;

private:
    mysqlpp::Connection m_Connection;
};

#endif // DATABASE_H
