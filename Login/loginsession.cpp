#include "loginsession.h"

const char* g_STS_Ping              = "/Sts/Ping STS/1.0";
const char* g_STS_Connect           = "/Sts/Connect STS/1.0";
const char* g_AUTH_StartTLS         = "/Auth/StartTls STS/1.0";
const char* g_AUTH_GetHost          = "/Auth/GetHostname STS/1.0";
const char* g_AUTH_StartSsoLogin    = "/Auth/StartSsoLogin STS/1.0";
const char* g_AUTH_ListGameAcc      = "/Account/ListMyGameAccounts STS/1.0";
const char* g_AUTH_Logout           = "/Auth/LogoutMyClient STS/1.0";
const char* g_AUTH_RequestGameToken = "/Auth/RequestGameToken STS/1.0";

LoginSession::LoginSession(ClientConnection *Client) : m_Client(Client), m_ConnectionType(0), m_Program(0),
    m_Build(0), m_Process(0), m_SendPackets(), m_TSLReady(false), m_LogoutRequested(false)
{

}

bool LoginSession::Recieve(XMLPacket *Packet)
{
    if (!Packet) {
        return false;
    }

    if (strncmp(Packet->m_Path, g_STS_Ping, sizeof(Packet->m_Path)) == 0) {
        printf("%s -> Ping!\n", m_Client->m_ClientIP);
    }

    else if (strncmp(Packet->m_Path, g_STS_Connect, sizeof(Packet->m_Path)) == 0) {
        Init(Packet);
    }

    else if (strncmp(Packet->m_Path, g_AUTH_StartTLS, sizeof(Packet->m_Path)) == 0) {
        StartTLS(Packet);
    }

    else if (strncmp(Packet->m_Path, g_AUTH_GetHost, sizeof(Packet->m_Path)) == 0) {
        GetHostname(Packet);
    }

    else if (strncmp(Packet->m_Path, g_AUTH_StartSsoLogin, sizeof(Packet->m_Path)) == 0) {
        StartSsoLogin(Packet);
    }

    else if (strncmp(Packet->m_Path, g_AUTH_ListGameAcc, sizeof(Packet->m_Path)) == 0) {
        ListGameAccounts(Packet);
    }

    else if (strncmp(Packet->m_Path, g_AUTH_RequestGameToken, sizeof(Packet->m_Path)) == 0) {
        RequestGameToken(Packet);
    }

    else if (strncmp(Packet->m_Path, g_AUTH_Logout, sizeof(Packet->m_Path)) == 0) {
        Logout(Packet);
    }

    else {
        printf("Unknown command: %s\n", Packet->m_Path);
    }

    return true;
}

void LoginSession::Send(SecureLogin *tlsClient)
{
    /*if (m_TLSSendNeeded) {
        tlsClient->Send(m_TLSSendBuffer, m_TLSSendBufferLength);
        m_TLSSendNeeded = false;
        memset(m_TLSSendBuffer, 0, 4096);
    }*/

    for (auto& message : m_SendPackets) {
        if (message.m_TLSSendNeeded) {
            tlsClient->Send(message.m_TLSSendBuffer, message.m_TLSSendBufferLength);
            message.m_TLSSendNeeded = false;
            memset(message.m_TLSSendBuffer, 0, 4096);
        }
    }

    m_SendPackets.clear();
}

void LoginSession::Init(XMLPacket *Packet)
{
    rapidxml::xml_node<>* connect_node = Packet->m_XMLDocument.first_node("Connect");

    m_ConnectionType = atoi(connect_node->first_node("ConnType")->value());
    m_Program = atoi(connect_node->first_node("Program")->value());
    m_Build = atoi(connect_node->first_node("Build")->value());
    m_Process = atoi(connect_node->first_node("Process")->value());

    printf("%s -> Client Query { Type: %d , Program: %d, Build: %d, Process: %d }\n", m_Client->m_ClientIP, m_ConnectionType,
           m_Program, m_Build, m_Process);
}

void LoginSession::StartTLS(XMLPacket *Packet)
{
    char response[512];
    printf("%s -> TLS Session Requested\n", m_Client->m_ClientIP);
    int sequence = Packet->m_Meta[2] - '0';

    // Do not bother with a formal reply, there does not seem to be any variation in this call
    sprintf(response, "STS/1.0 400 Success\r\ns:%dR\r\nl:%d\r\n\r\n<Error server=\"1001\" module=\"4\" line=\"262\"/>\n", sequence, 45);
    m_Client->Send(response, strlen(response));
    m_TSLReady = true;
}

void LoginSession::GetHostname(XMLPacket *Packet)
{
    rapidxml::xml_node<>* requestNode = Packet->m_XMLDocument.first_node("Request");
    bool validUser  = false;
    int userId      = -1;
    std::string userRegion;
    std::string userGateway;

    // TODO: hook the below code up to the database, we may
    // want to send them to a diffrent server if say portal = bot?
    auto loginName  = requestNode->first_node("LoginName")->value();
    auto provider   = requestNode->first_node("Provider")->value();

    try {
        auto userQuery = Database::Get().PrepareQuery("SELECT * FROM cligate.Users where userEmail = %0q;");
        auto gatewayQuery = Database::Get().PrepareQuery("SELECT * FROM cligate.Gates WHERE gateRegion = %0q;");

        auto result = userQuery.store(loginName);
        if (result.size() != 0) {
            validUser   = true;
            if (result.size() > 1) {
                printf("Data consistency error, an email address appear's more than once in the users table.");
            }
            userId      = atoi(std::string(result.front()["userId"]).c_str());
            userRegion  = std::string(result.front()["userRegion"]).c_str();
        }

        result = gatewayQuery.store(userRegion);
        if (result.size() != 0) {
            validUser   = true;
            if (result.size() > 1) {
                printf("Data consistency error, more than one gateway exists for a region.");
            }
            userGateway  = std::string(result.front()["gateAddress"]).c_str();
        }

    }
    catch (const mysqlpp::BadQuery& er) {
        std::cerr << "Query error: " << er.what() << std::endl;
        m_LogoutRequested = true;
        return;
    }
    catch (const mysqlpp::BadConversion& er) {
        std::cerr << "Conversion error: " << er.what() << std::endl <<
                "\tretrieved data size: " << er.retrieved <<
                ", actual size: " << er.actual_size << std::endl;
        m_LogoutRequested = true;
        return;
    }
    catch (const mysqlpp::Exception& er) {
        std::cerr << "Error: " << er.what() << std::endl;
        m_LogoutRequested = true;
        return;
    }

    // Debug message.
    printf("User %s is logging in using %s\n", loginName, provider);
    printf("Forwarding %s to %s\n", loginName, userGateway.c_str());
    int sequence = Packet->m_Meta[2] - '0';

    // Form a packet, the only element is the detination host name
    // GW2 will then try to connect to the specified server.
    GW2Packet replyPacket("", sequence, PT_REPLY);
    replyPacket.AddElement("Hostname", userGateway.c_str());
    //replyPacket.AddElement("Hostname", "cligate-fra.101.ncplatform.net.");

    // Signal that there is TLS data to be sent next time round.
    SessionSendPacket packet;
    memset(packet.m_TLSSendBuffer, 0, 4096);
    sprintf(packet.m_TLSSendBuffer, replyPacket.Payload());
    packet.m_TLSSendBufferLength = strlen(packet.m_TLSSendBuffer);
    packet.m_TLSSendNeeded = true;
    m_SendPackets.push_back(packet);
}

void LoginSession::StartSsoLogin(XMLPacket *Packet)
{
    rapidxml::xml_node<>* requestNode = Packet->m_XMLDocument.first_node("Request");

    char password[1024];
    memset(password, 0, 1024);
    int passwordLength = -1;
    char* emailaddress = nullptr;
    char* passwordBase64 = nullptr;
    std::string sha256Password;
    std::string guid;
    std::string username;

    try {
        emailaddress = requestNode->first_node("LoginName")->value();
        if (requestNode->first_node("Password") != nullptr) {
            passwordBase64 = requestNode->first_node("Password")->value();
            auto    bio = BIO_new_mem_buf(passwordBase64, -1);
            auto    b64 = BIO_new(BIO_f_base64());
                    bio = BIO_push(b64, bio);

            BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
            passwordLength = BIO_read(bio, password, strlen(passwordBase64));
            BIO_free_all(bio);
        }

        auto userQuery = Database::Get().PrepareQuery("SELECT * FROM cligate.Users where userEmail = %0q;");
        auto result = userQuery.store(emailaddress);
        if (result.size() != 0) {
            if (result.size() > 1) {
                printf("Data consistency error, an email address appear's more than once in the users table.");
            }
            sha256Password  = std::string(result.front()["userPassword"]).c_str();
            guid            = std::string(result.front()["userGuid"]).c_str();
            username        = std::string(result.front()["userName"]).c_str();
        }
    }
    catch(std::exception ex)
    {
        printf("Password tokens not supported.\n");
        return;
    }
    catch (const mysqlpp::BadQuery& er) {
        std::cerr << "Query error: " << er.what() << std::endl;
        m_LogoutRequested = true;
        return;
    }
    catch (const mysqlpp::BadConversion& er) {
        std::cerr << "Conversion error: " << er.what() << std::endl <<
                "\tretrieved data size: " << er.retrieved <<
                ", actual size: " << er.actual_size << std::endl;
        m_LogoutRequested = true;
        return;
    }
    catch (const mysqlpp::Exception& er) {
        std::cerr << "Error: " << er.what() << std::endl;
        m_LogoutRequested = true;
        return;
    }

    // TODO: add support for resume tokens
    if (passwordBase64 == nullptr) {
        printf("Resume tokens not supported yet\n");
        m_TSLReady = false;
        return;
    }

    //printf("Login >> %s with %s\n", username, password);
    eSHA256::SHA256 sha256;
    if (sha256(password).compare(sha256Password) != 0) {
        printf("email %s entered an incorrect password\n", emailaddress);
        m_LogoutRequested = true;
        return;
    }

    int sequence = Packet->m_Meta[2] - '0';

    std::string resumetoken = CreateGuid();

    //const char* temporary_guid = "0687C32C-0331-E611-80C3-ECB1D78A5C75";
    //const char* temporary_username = "nomelx.devel";

    GW2Packet replyPacket("", sequence, PT_REPLY);
    replyPacket.AddElement("UserId", guid.c_str());
    replyPacket.AddElement("UserCenter", "5");
    replyPacket.AddElement("UserName", username.c_str());
    replyPacket.AddElement("Parts", "");
    replyPacket.AddElement("ResumeToken", resumetoken.c_str());
    replyPacket.AddElement("EmailVerified", "1");


    SessionSendPacket packet;
    memset(packet.m_TLSSendBuffer, 0, 4096);
    sprintf(packet.m_TLSSendBuffer, replyPacket.Payload());
    packet.m_TLSSendBufferLength = strlen(packet.m_TLSSendBuffer);
    packet.m_TLSSendNeeded = true;
    m_SendPackets.push_back(packet);
}

void LoginSession::ListGameAccounts(XMLPacket *Packet)
{
    rapidxml::xml_node<>* requestNode = Packet->m_XMLDocument.first_node("Request");
    auto gameCode = requestNode->first_node("GameCode")->value();

    /*GW2Packet packet = GW2Packet("/Presence/UserInfo", PT_MESSAGE);
    packet.AddElement("Status", "online");
    packet.AddElement("Status", "online");*/

    printf("Looking up game accounts...\n");
    int sequence = Packet->m_Meta[2] - '0';

    const char* temporary_guid = "068XXXXC-XXXX-XXXX-XXXX-XXXXD7XXXX75";
    const char* temporary_username = "nomelx.devel";

    GW2Packet messagePacket("/Presence/UserInfo", sequence, PT_MESSAGE);
    messagePacket.AddElement("Status", "online");
    messagePacket.AddElement("Aliases", "");
    messagePacket.AddElement("OnlineTimes", "");
    messagePacket.AddElement("AppData", "");
    messagePacket.AddElement("Channels", "");
    messagePacket.AddElement("Groups", "");
    messagePacket.AddElement("Contacts", "");
    messagePacket.AddElement("UserId", temporary_guid);
    messagePacket.AddElement("UserCenter", "5");
    messagePacket.AddElement("UserName", temporary_username);
    messagePacket.AddElement("ChangeId", "20");
    messagePacket.AddElement("NewBeginning", "");

    std::string compiledReply = "";
    std::string temporaryGameList[] = {
        "STS/1.0 200 OK\r\n",
        "s:"+std::to_string(sequence)+"R\r\n",
        "l:136\r\n",
        "\r\n",
        "<Reply type=\"array\">\n",
        "<Row>\n"
        "<GameCode>gw2</GameCode>\n"
        "<Alias>Guild Wars 2</Alias>\n"
        "<Created>2016-06-13T01:07:20Z</Created>\n"
        "</Row>\n"
        "</Reply>\n"
    };
    for (auto line : temporaryGameList) {
        compiledReply += line;
    }

    SessionSendPacket message;
    memset(message.m_TLSSendBuffer, 0, 4096);
    sprintf(message.m_TLSSendBuffer, messagePacket.Payload());
    message.m_TLSSendBufferLength = strlen(message.m_TLSSendBuffer);
    message.m_TLSSendNeeded = true;
    m_SendPackets.push_back(message);

    SessionSendPacket gameArray;
    memset(gameArray.m_TLSSendBuffer, 0, 4096);
    sprintf(gameArray.m_TLSSendBuffer, compiledReply.c_str());
    gameArray.m_TLSSendBufferLength = strlen(gameArray.m_TLSSendBuffer);
    gameArray.m_TLSSendNeeded = true;
    m_SendPackets.push_back(gameArray);
}

void LoginSession::RequestGameToken(XMLPacket *Packet)
{
    rapidxml::xml_node<>* requestNode = Packet->m_XMLDocument.first_node("Request");
    auto gameCode = requestNode->first_node("GameCode")->value();
    auto accountAlias = requestNode->first_node("AccountAlias")->value();

    printf("Generating Session Token.\n");
    int sequence = Packet->m_Meta[2] - '0';

    // Form a packet, the only element is the detination host name
    // GW2 will then try to connect to the specified server.
    GW2Packet replyPacket("", sequence, PT_REPLY);
    replyPacket.AddElement("Token", "0XXXX32C-XXXX-XXXX-XXXX-XXXXD78XXXX5");

    // Signal that there is TLS data to be sent next time round.
    SessionSendPacket packet;
    memset(packet.m_TLSSendBuffer, 0, 4096);
    sprintf(packet.m_TLSSendBuffer, replyPacket.Payload());
    packet.m_TLSSendBufferLength = strlen(packet.m_TLSSendBuffer);
    packet.m_TLSSendNeeded = true;
    m_SendPackets.push_back(packet);

    printf("Handing client to Auth2.101.ArenaNetworks.com\n");
}

void LoginSession::Logout(XMLPacket *Packet)
{
    m_LogoutRequested = true;
}

std::string LoginSession::CreateGuid()
{
    uuid_t id;
    uuid_generate(id);
    char guidString[256];
    uuid_unparse(id, guidString);
    return std::string(guidString);
}
