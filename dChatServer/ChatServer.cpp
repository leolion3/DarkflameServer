#include <chrono>
#include <iostream>
#include <string>
#include <thread>

//DLU Includes:
#include "ChatPacketHandler.h"
#include "Database.h"
#include "Diagnostics.h"
#include "Game.h"
#include "PlayerContainer.h"
#include "dChatFilter.h"
#include "dCommonVars.h"
#include "dConfig.h"
#include "dLogger.h"
#include "dMessageIdentifiers.h"
#include "dServer.h"
namespace Game {
dLogger* logger;
dServer* server;
dConfig* config;
dChatFilter* chatFilter;
} // namespace Game

//RakNet includes:
#include "RakNetDefines.h"

dLogger* SetupLogger();
void HandlePacket(Packet* packet);

PlayerContainer playerContainer;

void flushServerLogs();
int checkConnectionToMaster();
void prepareDiagnostics(char** argv);
void printServerDetails();
int prepareServer();
void setGameConfigs(dConfig* config);
int connectToDatabase(dConfig* config);
void getServerAddressAndConnect(dConfig* config);
void createServer(dConfig* config, std::string masterIP, int masterPort);
void keepDatabaseConnectionAlive();
void pingDatabase();
void handleServerPackets();
void destroyOnExit();

int framesSinceLastFlush = 0;
int framesSinceMasterDisconnect = 0;
int framesSinceLastSQLPing = 0;

int main(int argc, char** argv) {
    prepareDiagnostics(argv);
    Game::logger = SetupLogger();
    if (!Game::logger)
        return 0;
    printServerDetails();
    dConfig config("chatconfig.ini");
    setGameConfigs(&config);
    if (connectToDatabase(&config) == 0)
        return 0;
    getServerAddressAndConnect(&config);
	Game::chatFilter = new dChatFilter("./res/chatplus_en_us", bool(std::stoi(config.GetValue("dont_generate_dcf"))));

    //Run it until server gets a kill message from Master:
    auto t = std::chrono::high_resolution_clock::now();
    while (true) {
        if (checkConnectionToMaster() == 0)
            break;
        handleServerPackets();
        flushServerLogs();
        keepDatabaseConnectionAlive();
        //Sleep our thread since auth can afford to.
        t += std::chrono::milliseconds(mediumFramerate); //Chat can run at a lower "fps"
        std::this_thread::sleep_until(t);
    }
    destroyOnExit();
    exit(EXIT_SUCCESS);
    return EXIT_SUCCESS;
}

/**
* Prepare server diagnostics
*/
void prepareDiagnostics(char** argv) {
    Diagnostics::SetProcessName("Chat");
    Diagnostics::SetProcessFileName(argv[0]);
    Diagnostics::Initialize();
}

/**
* Print some details about the server
*/
void printServerDetails() {
    Game::logger->Log("ChatServer", "Starting Chat server...");
    Game::logger->Log("ChatServer", "Version: %i.%i", PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR);
    Game::logger->Log("ChatServer", "Compiled on: %s", __TIMESTAMP__);
}

/**
* @brief Prepare game configs
*/
void setGameConfigs(dConfig* configPointer) {
    dConfig config = *configPointer;
    Game::config = configPointer;
    Game::logger->SetLogToConsole(bool(std::stoi(config.GetValue("log_to_console"))));
    Game::logger->SetLogDebugStatements(config.GetValue("log_debug_statements") == "1");
}

/**
	* @brief Connect to MySQL Database
	* @param config - game configurations
	* @return 1 if the connection succeeded, else 0
*/
int connectToDatabase(dConfig* configPointer) {
    dConfig config = *configPointer;
    //Connect to the MySQL Database
    std::string mysql_host = config.GetValue("mysql_host");
    std::string mysql_database = config.GetValue("mysql_database");
    std::string mysql_username = config.GetValue("mysql_username");
    std::string mysql_password = config.GetValue("mysql_password");

    try {
        Database::Connect(mysql_host, mysql_database, mysql_username, mysql_password);
        return 1;
    } catch (sql::SQLException& ex) {
        Game::logger->Log("ChatServer", "Got an error while connecting to the database: %s", ex.what());
        Database::Destroy("ChatServer");
        delete Game::server;
        delete Game::logger;
        return 0;
    }
}

/**
	* @brief Gets the server's IP and creates the server
	* @param config - the server configurations
*/
void getServerAddressAndConnect(dConfig* config) {
    //Find out the master's IP:
    std::string masterIP;
    int masterPort = 1000;
    sql::PreparedStatement* stmt = Database::CreatePreppedStmt("SELECT ip, port FROM servers WHERE name='master';");
    auto res = stmt->executeQuery();
    while (res->next()) {
        masterIP = res->getString(1).c_str();
        masterPort = res->getInt(2);
    }
    delete res;
    delete stmt;
    createServer(config, masterIP, masterPort);
}

/**
	* @brief Set up this server
	* @param config - server configs
	* @param masterIP - the IP address of the server
	* @param masterPort - the port the server should run on
*/
void createServer(dConfig* configPointer, std::string masterIP, int masterPort) {
    //It's safe to pass 'localhost' here, as the IP is only used as the external IP.
    dConfig config = *configPointer;
    int maxClients = 50;
    int ourPort = 1501;
    if (config.GetValue("max_clients") != "")
        maxClients = std::stoi(config.GetValue("max_clients"));
    if (config.GetValue("port") != "")
        ourPort = std::atoi(config.GetValue("port").c_str());

    Game::server = new dServer(config.GetValue("external_ip"), ourPort, 0, maxClients, false, true, Game::logger, masterIP, masterPort, ServerType::Chat);
}

/**
	* Keep database connection alive by pinging it every 10 minutes
*/
void keepDatabaseConnectionAlive() {
    if (framesSinceLastSQLPing < 40000) {
        framesSinceLastSQLPing++;
        return;
    }
    pingDatabase();
    framesSinceLastSQLPing = 0;
}

void pingDatabase() {
    //Find out the master's IP for absolutely no reason:
    std::string masterIP;
    int masterPort;
    sql::PreparedStatement* stmt = Database::CreatePreppedStmt("SELECT ip, port FROM servers WHERE name='master';");
    auto res = stmt->executeQuery();
    while (res->next()) {
        masterIP = res->getString(1).c_str();
        masterPort = res->getInt(2);
    }
    delete res;
    delete stmt;
}

/**
	* @brief Handle data packets
*/
void handleServerPackets() {
    Packet* packet = nullptr;
    Game::server->ReceiveFromMaster(); //ReceiveFromMaster also handles the master packets if needed.
    packet = Game::server->Receive();
    if (packet) {
        HandlePacket(packet);
        Game::server->DeallocatePacket(packet);
        packet = nullptr;
    }
}

/**
	* @brief Check the connection to Master
*/
int checkConnectionToMaster() {
    //Check if we're still connected to master:
    if (Game::server->GetIsConnectedToMaster()) {
        framesSinceMasterDisconnect = 0;
        return 1;
    }
    framesSinceMasterDisconnect++;
    // If the server has been disconnected for more than 10 minutes, shut down.
    if (framesSinceMasterDisconnect >= 40000)
        return 0;
    return 1;
}

/**
	* @brief Flush server logs every 30 seconds
*/
void flushServerLogs() {
    if (framesSinceLastFlush < 900) {
        framesSinceLastFlush++;
        return;
    }
    Game::logger->Flush();
    framesSinceLastFlush = 0;
}

void destroyOnExit() {
    Database::Destroy("ChatServer");
    delete Game::server;
    delete Game::logger;
}

dLogger* SetupLogger() {
    std::string logPath = "./logs/ChatServer_" + std::to_string(time(nullptr)) + ".log";
    bool logToConsole = false;
    bool logDebugStatements = false;
#ifdef _DEBUG
    logToConsole = true;
    logDebugStatements = true;
#endif

    return new dLogger(logPath, logToConsole, logDebugStatements);
}

void HandlePacket(Packet* packet) {
    if (packet->data[0] == ID_DISCONNECTION_NOTIFICATION || packet->data[0] == ID_CONNECTION_LOST) {
        Game::logger->Log("ChatServer", "A server has disconnected, erasing their connected players from the list.");
    }

    if (packet->data[0] == ID_NEW_INCOMING_CONNECTION) {
        Game::logger->Log("ChatServer", "A server is connecting, awaiting user list.");
    }

    if (packet->data[1] == CHAT_INTERNAL) {
        switch (packet->data[3]) {
            case MSG_CHAT_INTERNAL_PLAYER_ADDED_NOTIFICATION:
                playerContainer.InsertPlayer(packet);
                break;

            case MSG_CHAT_INTERNAL_PLAYER_REMOVED_NOTIFICATION:
                playerContainer.RemovePlayer(packet);
                break;

            case MSG_CHAT_INTERNAL_MUTE_UPDATE:
                playerContainer.MuteUpdate(packet);
                break;

            case MSG_CHAT_INTERNAL_CREATE_TEAM:
                playerContainer.CreateTeamServer(packet);
                break;

            case MSG_CHAT_INTERNAL_ANNOUNCEMENT: {
                //we just forward this packet to every connected server
                CINSTREAM;
                Game::server->Send(&inStream, packet->systemAddress, true); //send to everyone except origin
                break;
            }

            default:
                Game::logger->Log("ChatServer", "Unknown CHAT_INTERNAL id: %i", int(packet->data[3]));
        }
    }

    if (packet->data[1] == CHAT) {
        switch (packet->data[3]) {
            case MSG_CHAT_GET_FRIENDS_LIST:
                ChatPacketHandler::HandleFriendlistRequest(packet);
                break;

            case MSG_CHAT_GET_IGNORE_LIST:
                Game::logger->Log("ChatServer", "Asked for ignore list, but is unimplemented right now.");
                break;

            case MSG_CHAT_TEAM_GET_STATUS:
                ChatPacketHandler::HandleTeamStatusRequest(packet);
                break;

            case MSG_CHAT_ADD_FRIEND_REQUEST:
                //this involves someone sending the initial request, the response is below, response as in from the other player.
                //We basically just check to see if this player is online or not and route the packet.
                ChatPacketHandler::HandleFriendRequest(packet);
                break;

            case MSG_CHAT_ADD_FRIEND_RESPONSE:
                //This isn't the response a server sent, rather it is a player's response to a received request.
                //Here, we'll actually have to add them to eachother's friend lists depending on the response code.
                ChatPacketHandler::HandleFriendResponse(packet);
                break;

            case MSG_CHAT_REMOVE_FRIEND:
                ChatPacketHandler::HandleRemoveFriend(packet);
                break;

            case MSG_CHAT_GENERAL_CHAT_MESSAGE:
                ChatPacketHandler::HandleChatMessage(packet);
                break;

            case MSG_CHAT_PRIVATE_CHAT_MESSAGE:
                //This message is supposed to be echo'd to both the sender and the receiver
                //BUT: they have to have different responseCodes, so we'll do some of the ol hacky wacky to fix that right up.
                ChatPacketHandler::HandlePrivateChatMessage(packet);
                break;

            case MSG_CHAT_TEAM_INVITE:
                ChatPacketHandler::HandleTeamInvite(packet);
                break;

            case MSG_CHAT_TEAM_INVITE_RESPONSE:
                ChatPacketHandler::HandleTeamInviteResponse(packet);
                break;

            case MSG_CHAT_TEAM_LEAVE:
                ChatPacketHandler::HandleTeamLeave(packet);
                break;

            case MSG_CHAT_TEAM_SET_LEADER:
                ChatPacketHandler::HandleTeamPromote(packet);
                break;

            case MSG_CHAT_TEAM_KICK:
                ChatPacketHandler::HandleTeamKick(packet);
                break;

            case MSG_CHAT_TEAM_SET_LOOT:
                ChatPacketHandler::HandleTeamLootOption(packet);
                break;

            default:
                Game::logger->Log("ChatServer", "Unknown CHAT id: %i", int(packet->data[3]));
        }
    }

    if (packet->data[1] == WORLD) {
        switch (packet->data[3]) {
            case MSG_WORLD_CLIENT_ROUTE_PACKET: {
                Game::logger->Log("ChatServer", "Routing packet from world");
                break;
            }

            default:
                Game::logger->Log("ChatServer", "Unknown World id: %i", int(packet->data[3]));
        }
    }
}
