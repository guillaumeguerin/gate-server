#include "database.h"

Database* Database::g_Instance = nullptr;

Database::Database() : m_Connection()
{
}

Database::~Database()
{
}

Database *Database::GetPtr()
{
    if (g_Instance == nullptr) {
        g_Instance = new Database();
    }
    return g_Instance;
}

Database &Database::Get()
{
    return *GetPtr();
}

bool Database::Initalize(const char* database, const char *serverAddress, const char *username, const char *password, unsigned int port)
{
    auto connected = m_Connection.connect(database, serverAddress, username, password, port);
    if (!connected) {
        return false;
    }

    return true;
}

mysqlpp::StoreQueryResult Database::RunQuery(const char *runQuery)
{
    mysqlpp::StoreQueryResult result;

    try {
        mysqlpp::Query dbQuery = m_Connection.query(runQuery);
        result = dbQuery.store();

    } catch (mysqlpp::BadQuery badQueryException) {
        printf("Exception: %s", badQueryException.what());
    } catch (mysqlpp::Exception ex) {
        printf("Exception: %s", ex.what());
    }

    return result;
}
