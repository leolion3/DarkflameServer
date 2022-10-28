#include <chrono>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>

#include "MD5.h"

//DLU Includes:
#include "Database.h"
#include "Diagnostics.h"
#include "Metrics.hpp"
#include "PerformanceManager.h"
#include "dCommonVars.h"
#include "dConfig.h"
#include "dLogger.h"
#include "dServer.h"
#include "dZoneManager.h"
#include "dpWorld.h"

//RakNet includes:
#include "RakNetDefines.h"
#include "RakNetworkFactory.h"
#include "RakString.h"

//World includes:
#include <csignal>

#include "AuthPackets.h"
#include "CDClientDatabase.h"
#include "CDClientManager.h"
#include "Character.h"
#include "CharacterComponent.h"
#include "ChatPackets.h"
#include "ClientPackets.h"
#include "DestroyableComponent.h"
#include "Entity.h"
#include "EntityManager.h"
#include "Game.h"
#include "GameMessageHandler.h"
#include "GameMessages.h"
#include "GeneralUtils.h"
#include "Mail.h"
#include "MasterPackets.h"
#include "ObjectIDManager.h"
#include "PacketUtils.h"
#include "Player.h"
#include "PropertyManagementComponent.h"
#include "SkillComponent.h"
#include "TeamManager.h"
#include "UserManager.h"
#include "WorldPackets.h"
#include "ZCompression.h"
#include "ZoneInstanceManager.h"
#include "dChatFilter.h"
#include "dLocale.h"
#include "dMessageIdentifiers.h"

namespace Game {
dLogger* logger;
dServer* server;
dZoneManager* zoneManager;
dpWorld* physicsWorld;
dChatFilter* chatFilter;
dConfig* config;
dLocale* locale;
std::mt19937 randomEngine;

RakPeerInterface* chatServer;
SystemAddress chatSysAddr;
} // namespace Game

void WorldShutdownSequence();
void WorldShutdownProcess(uint32_t zoneId);
void FinalizeShutdown();
void SendShutdownMessageToMaster();

dLogger* SetupLogger(int zoneID, int instanceID);
void HandlePacketChat(Packet* packet);
void HandlePacket(Packet* packet);

struct tempSessionInfo {
    SystemAddress sysAddr;
    std::string hash;
};

Packet* packet = nullptr;
std::map<std::string, tempSessionInfo> m_PendingUsers;
std::string databaseChecksum = "";
std::string masterIP = "";
const float maxPacketProcessingTime = 1.5f; //0.015f;
int instanceID = 0;
int g_CloneID = 0;
int zoneID = 1000;
int cloneID = 0;
int maxClients = 8;
int ourPort = 2007;
int framesSinceLastFlush = 0;
int framesSinceMasterDisconnect = 0;
int framesSinceChatDisconnect = 0;
int framesSinceLastUsersSave = 0;
int framesSinceLastSQLPing = 0;
int framesSinceLastUser = 0;
int masterPort = 0;
int chatPort = 1501;
const int maxPacketsToProcess = 1024;
int framesSinceMasterStatus = 0;
int framesSinceShutdownSequence = 0;
int currentFramerate = highFrameRate;
int ghostingStepCount = 0;
const int framesToWaitForMaster = 40000;
bool ready = false;
bool chatDisabled = false;
bool chatConnected = false;
bool worldShutdownSequenceStarted = false;
bool worldShutdownSequenceComplete = false;

namespace WorldServer {
void prepareDiagnostics(char** argv);
void checkArgs(int argc, char** argv);
int prepareLogger();
void setGameConfigs(dConfig config);
int connectToClientDB();
int connectToMySQL(dConfig config);
void getServerAddressAndConnect(dConfig config);
void createServer(dConfig config, std::string masterIP, int masterPort);
void connectChatServer(dConfig config, std::string masterIP);
void prepareZone();
void checkConnectionToMaster();
void checkCurrentFrameRate(float deltaTime);
void checkConnectionToChatServer();
void handleMetrics(float deltaTime, std::chrono::_V2::system_clock::time_point currentTime, std::chrono::_V2::system_clock::time_point ghostingLastTime);
void handleRegularPacket();
void handleChatPacket();
void flushServerLogs();
void checkForPlayers(bool occupied);
void savePlayers();
void keepDatabaseConnectionAlive();
void pingDatabase();
void loadWorld();
int handleWorldPackets();
} // namespace WorldServer

int main(int argc, char** argv) {
    WorldServer::prepareDiagnostics(argv);

    // Triggers the shutdown sequence at application exit
    std::atexit(WorldShutdownSequence);

    signal(SIGINT, [](int) { WorldShutdownSequence(); });
    signal(SIGTERM, [](int) { WorldShutdownSequence(); });
    WorldServer::checkArgs(argc, argv);
    if (WorldServer::prepareLogger() == 0)
        return 0;
    dConfig config("worldconfig.ini");
    WorldServer::setGameConfigs(config);

    if (WorldServer::connectToClientDB() == 0)
        return -1;
    if (WorldServer::connectToMySQL(config) == 0)
        return 0;

    WorldServer::getServerAddressAndConnect(config);

    //Set up other things:
    Game::randomEngine = std::mt19937(time(0));
    Game::locale = new dLocale();

    //Run it until server gets a kill message from Master:
    auto lastTime = std::chrono::high_resolution_clock::now();
    auto t = std::chrono::high_resolution_clock::now();

    auto ghostingLastTime = std::chrono::high_resolution_clock::now();

    PerformanceManager::SelectProfile(zoneID);
    if (zoneID != 0)
        WorldServer::prepareZone();

    while (true) {
        Metrics::StartMeasurement(MetricVariable::Frame);
        Metrics::StartMeasurement(MetricVariable::GameLoop);
        std::clock_t metricCPUTimeStart = std::clock();
        const auto currentTime = std::chrono::high_resolution_clock::now();
        float deltaTime = std::chrono::duration<float>(currentTime - lastTime).count();
        lastTime = currentTime;
        const auto occupied = UserManager::Instance()->GetUserCount() != 0;
        WorldServer::checkCurrentFrameRate(deltaTime);
        WorldServer::checkConnectionToMaster();
        WorldServer::checkConnectionToChatServer();
        //In world we'd update our other systems here.
        WorldServer::handleMetrics(deltaTime, currentTime, ghostingLastTime);
        Metrics::StartMeasurement(MetricVariable::PacketHandling);
        WorldServer::handleRegularPacket();
        WorldServer::handleChatPacket();
        if (WorldServer::handleWorldPackets() == 0) break;
        Metrics::EndMeasurement(MetricVariable::PacketHandling);
        Metrics::StartMeasurement(MetricVariable::UpdateReplica);
        //Update our replica objects:
        Game::server->UpdateReplica();
        Metrics::EndMeasurement(MetricVariable::UpdateReplica);
        WorldServer::flushServerLogs();
        WorldServer::checkForPlayers(occupied);
        WorldServer::savePlayers();
        WorldServer::keepDatabaseConnectionAlive();
        Metrics::EndMeasurement(MetricVariable::GameLoop);
        Metrics::StartMeasurement(MetricVariable::Sleep);
        t += std::chrono::milliseconds(currentFramerate);
        std::this_thread::sleep_until(t);
        Metrics::EndMeasurement(MetricVariable::Sleep);
        WorldServer::loadWorld();
        if (worldShutdownSequenceStarted && !worldShutdownSequenceComplete) {
            WorldShutdownProcess(zoneID);
            break;
        }
        Metrics::AddMeasurement(MetricVariable::CPUTime, (1e6 * (1000.0 * (std::clock() - metricCPUTimeStart))) / CLOCKS_PER_SEC);
        Metrics::EndMeasurement(MetricVariable::Frame);
    }
    FinalizeShutdown();
    return EXIT_SUCCESS;
}

/**
* Prepare server diagnostics
*/
void WorldServer::prepareDiagnostics(char** argv) {
    Diagnostics::SetProcessName("World");
    Diagnostics::SetProcessFileName(argv[0]);
    Diagnostics::Initialize();
}

/**
 * @brief Update server settings based on commandline args
*/
void WorldServer::checkArgs(int argc, char** argv) {
    for (int i = 0; i < argc; ++i) {
        std::string argument(argv[i]);
        if (argument == "-zone")
            zoneID = atoi(argv[i + 1]);
        if (argument == "-instance")
            instanceID = atoi(argv[i + 1]);
        if (argument == "-clone")
            cloneID = atoi(argv[i + 1]);
        if (argument == "-maxclients")
            maxClients = atoi(argv[i + 1]);
        if (argument == "-port")
            ourPort = atoi(argv[i + 1]);
    }
}

/**
 * @brief Prepare server logger
 * @return 0 if the setup failed, 1 otherwise
*/
int WorldServer::prepareLogger() {
    Game::logger = SetupLogger(zoneID, instanceID);
    if (!Game::logger)
        return 0;
    Game::logger->SetLogToConsole(true); //We want this info to always be logged.
    Game::logger->Log("WorldServer", "Starting World server...");
    Game::logger->Log("WorldServer", "Version: %i.%i", PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR);
    Game::logger->Log("WorldServer", "Compiled on: %s", __TIMESTAMP__);
#ifndef _DEBUG
    Game::logger->SetLogToConsole(false); //By default, turn it back off if not in debug.
#endif
    return 1;
}

/**
* @brief Prepare game configs
*/
void WorldServer::setGameConfigs(dConfig config) {
    Game::config = &config;
    Game::logger->SetLogToConsole(bool(std::stoi(config.GetValue("log_to_console"))));
    Game::logger->SetLogDebugStatements(config.GetValue("log_debug_statements") == "1");
    if (config.GetValue("disable_chat") == "1")
        chatDisabled = true;
}

/**
 * @brief Connect to CDClient DB
 * @return 0 if the connection failed, 1 otherwise
*/
int WorldServer::connectToClientDB() {
    // Connect to CDClient
    try {
        CDClientDatabase::Connect("./res/CDServer.sqlite");
        CDClientManager::Instance()->Initialize();
        return 1;
    } catch (CppSQLite3Exception& e) {
        Game::logger->Log("WorldServer", "Unable to connect to CDServer SQLite Database");
        Game::logger->Log("WorldServer", "Error: %s", e.errorMessage());
        Game::logger->Log("WorldServer", "Error Code: %i", e.errorCode());
        return 0;
    }
}

/**
 * @brief Connect to MySQL Database
 * @param config - server configs
 * @return 0 if the connection failed, 1 otherwise
*/
int WorldServer::connectToMySQL(dConfig config) {
    std::string mysql_host = config.GetValue("mysql_host");
    std::string mysql_database = config.GetValue("mysql_database");
    std::string mysql_username = config.GetValue("mysql_username");
    std::string mysql_password = config.GetValue("mysql_password");

    Diagnostics::SetProduceMemoryDump(config.GetValue("generate_dump") == "1");

    if (!config.GetValue("dump_folder").empty()) {
        Diagnostics::SetOutDirectory(config.GetValue("dump_folder"));
    }

    try {
        Database::Connect(mysql_host, mysql_database, mysql_username, mysql_password);
        return 1;
    } catch (sql::SQLException& ex) {
        Game::logger->Log("WorldServer", "Got an error while connecting to the database: %s", ex.what());
        return 0;
    }
}

/**
	* @brief Gets the server's IP and creates the server
	* @param config - the server configurations
*/
void WorldServer::getServerAddressAndConnect(dConfig config) {
    masterIP = "localhost";
    masterPort = 1000;
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
void WorldServer::createServer(dConfig config, std::string masterIP, int masterPort) {
    ObjectIDManager::Instance()->Initialize();
    UserManager::Instance()->Initialize();
    LootGenerator::Instance();
    Game::chatFilter = new dChatFilter("./res/chatplus_en_us", bool(std::stoi(config.GetValue("dont_generate_dcf"))));

    Game::server = new dServer(masterIP, ourPort, instanceID, maxClients, false, true, Game::logger, masterIP, masterPort, ServerType::World, zoneID);
    connectChatServer(config, masterIP);
}

/**
 * @brief Connect the ChatServer
*/
void WorldServer::connectChatServer(dConfig config, std::string masterIP) {
    if (config.GetValue("chat_server_port") != "")
        chatPort = std::atoi(config.GetValue("chat_server_port").c_str());

    auto chatSock = SocketDescriptor(uint16_t(ourPort + 2), 0);
    Game::chatServer = RakNetworkFactory::GetRakPeerInterface();
    Game::chatServer->Startup(1, 30, &chatSock, 1);
    Game::chatServer->Connect(masterIP.c_str(), chatPort, "3.25 ND1", 8);
}

/**
 * @brief Prepare a new world
*/
void WorldServer::prepareZone() {
    dpWorld::Instance().Initialize(zoneID);
    Game::physicsWorld = &dpWorld::Instance(); //just in case some old code references it
    dZoneManager::Instance()->Initialize(LWOZONEID(zoneID, instanceID, cloneID));
    g_CloneID = cloneID;

    // pre calculate the FDB checksum
    if (Game::config->GetValue("check_fdb") != "1")
        return;
    std::ifstream fileStream;

    static const std::vector<std::string> aliases = {
        "res/CDServers.fdb",
        "res/cdserver.fdb",
        "res/CDClient.fdb",
        "res/cdclient.fdb",
    };

    for (const auto& file : aliases) {
        fileStream.open(file, std::ios::binary | std::ios::in);
        if (fileStream.is_open()) {
            break;
        }
    }

    const int bufferSize = 1024;
    MD5* md5 = new MD5();

    char fileStreamBuffer[1024] = {};

    while (!fileStream.eof()) {
        memset(fileStreamBuffer, 0, bufferSize);
        fileStream.read(fileStreamBuffer, bufferSize);
        md5->update(fileStreamBuffer, fileStream.gcount());
    }

    fileStream.close();

    const char* nullTerminateBuffer = "\0";
    md5->update(nullTerminateBuffer, 1); // null terminate the data
    md5->finalize();
    databaseChecksum = md5->hexdigest();

    delete md5;

    Game::logger->Log("WorldServer", "FDB Checksum calculated as: %s", databaseChecksum.c_str());
}

/**
 * @brief Check if the MasterServer is still connected
*/
void WorldServer::checkConnectionToMaster() {
    if (Game::server->GetIsConnectedToMaster()) {
        framesSinceMasterDisconnect = 0;
        return;
    }
    framesSinceMasterDisconnect++;
    if (framesSinceMasterDisconnect >= framesToWaitForMaster && !worldShutdownSequenceStarted) {
        Game::logger->Log("WorldServer", "Game loop running but no connection to master for %d frames, shutting down", framesToWaitForMaster);
        worldShutdownSequenceStarted = true;
    }
}

/**
 * @brief Check if server is lagging behind
 * @param deltaTime - time since last frame
*/
void WorldServer::checkCurrentFrameRate(float deltaTime) {
    currentFramerate = !ready ? highFrameRate : PerformanceManager::GetServerFramerate();

    if (deltaTime > currentFramerate) {
        Game::logger->Log("WorldServer", "We're running behind, dT: %f > %f (framerate)", deltaTime, currentFramerate);
    }
}

/**
 * @brief Check if the chat server is still connected
*/
void WorldServer::checkConnectionToChatServer() {
    // Check if we're still connected to chat:
    if (chatConnected) {
        framesSinceChatDisconnect = 0;
        return;
    }
    framesSinceChatDisconnect++;
    // Attempt to reconnect every 30 seconds.
    if (framesSinceChatDisconnect < 2000)
        return;
    framesSinceChatDisconnect = 0;
    Game::chatServer->Connect(masterIP.c_str(), chatPort, "3.25 ND1", 8);
}

/**
 * @brief Measure some metrics about the world
*/
void WorldServer::handleMetrics(float deltaTime, std::chrono::_V2::system_clock::time_point currentTime, std::chrono::_V2::system_clock::time_point ghostingLastTime) {
    if (zoneID == 0 || deltaTime <= 0.0f)
        return;
    Metrics::StartMeasurement(MetricVariable::Physics);
    dpWorld::Instance().StepWorld(deltaTime);
    Metrics::EndMeasurement(MetricVariable::Physics);

    Metrics::StartMeasurement(MetricVariable::UpdateEntities);
    EntityManager::Instance()->UpdateEntities(deltaTime);
    Metrics::EndMeasurement(MetricVariable::UpdateEntities);

    Metrics::StartMeasurement(MetricVariable::Ghosting);
    if (std::chrono::duration<float>(currentTime - ghostingLastTime).count() >= 1.0f) {
        EntityManager::Instance()->UpdateGhosting();
        ghostingLastTime = currentTime;
    }
    Metrics::EndMeasurement(MetricVariable::Ghosting);

    Metrics::StartMeasurement(MetricVariable::UpdateSpawners);
    dZoneManager::Instance()->Update(deltaTime);
    Metrics::EndMeasurement(MetricVariable::UpdateSpawners);
}

/**
 * @brief Handle packets from MasterServer
*/
void WorldServer::handleRegularPacket() {
    //Check for packets here:
    packet = Game::server->ReceiveFromMaster();
    if (packet) { //We can get messages not handle-able by the dServer class, so handle them if we returned anything.
        HandlePacket(packet);
        Game::server->DeallocateMasterPacket(packet);
    }
}

/**
 * @brief Handle packets from ChatServer
*/
void WorldServer::handleChatPacket() {
    //Handle our chat packets:
    packet = Game::chatServer->Receive();
    if (packet) {
        HandlePacketChat(packet);
        Game::chatServer->DeallocatePacket(packet);
    }
}

/**
 * @brief Handle world specific packets
 * @return 0 if the packet was empty (error), 1 otherwise
*/
int WorldServer::handleWorldPackets() {
	//Handle world-specific packets:
    float timeSpent = 0.0f;
    UserManager::Instance()->DeletePendingRemovals();
    auto t1 = std::chrono::high_resolution_clock::now();
    for (int curPacket = 0; curPacket < maxPacketsToProcess && timeSpent < maxPacketProcessingTime; curPacket++) {
        packet = Game::server->Receive();
        if (!packet) return 0;
        auto t1 = std::chrono::high_resolution_clock::now();
        HandlePacket(packet);
        auto t2 = std::chrono::high_resolution_clock::now();

        timeSpent += std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        Game::server->DeallocatePacket(packet);
        packet = nullptr;
    }
	return 1;
}

/**
 * @brief Flush server logs every 15 seconds
*/
void WorldServer::flushServerLogs() {
    //Push our log every 15s:
    if (framesSinceLastFlush < 900) {
        framesSinceLastFlush++;
        return;
    }
    Game::logger->Flush();
    framesSinceLastFlush = 0;
}

/**
 * @brief Check the current world for players or shut down
*/
void WorldServer::checkForPlayers(bool occupied) {
    if (zoneID == 0 || occupied) {
        framesSinceLastUser = 0;
        return;
	}
    framesSinceLastUser++;
    //If we haven't had any players for a while, time out and shut down:
    if (framesSinceLastUser == (cloneID != 0 ? 4000 : framesToWaitForMaster)) {
        worldShutdownSequenceStarted = true;
    }
}

/**
 * @brief Save players every 10 minutes
*/
void WorldServer::savePlayers() {

    //Save all connected users every 10 minutes:
    if (framesSinceLastUsersSave < framesToWaitForMaster - 1 || zoneID == 0) {
        framesSinceLastUsersSave++;
        return;
	}
    UserManager::Instance()->SaveAllActiveCharacters();
    framesSinceLastUsersSave = 0;

    if (PropertyManagementComponent::Instance() != nullptr) {
        PropertyManagementComponent::Instance()->Save();
    }    
}

/**
	* Keep database connection alive by pinging it every 10 minutes
*/
void WorldServer::keepDatabaseConnectionAlive() {
	if (framesSinceLastSQLPing < framesToWaitForMaster) {
		framesSinceLastSQLPing++;
		return;
	}
	pingDatabase();
	framesSinceLastSQLPing = 0;
}

void WorldServer::pingDatabase() {
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
 * @brief Transfer player into world
*/
void WorldServer::loadWorld() {
	if (!ready && Game::server->GetIsConnectedToMaster()) {
        // Some delay is required here or else we crash the client?
        framesSinceMasterStatus++;
        if (framesSinceMasterStatus >= 200) {
            Game::logger->Log("WorldServer", "Finished loading world with zone (%i), ready up!", Game::server->GetZoneID());
            MasterPackets::SendWorldReady(Game::server, Game::server->GetZoneID(), Game::server->GetInstanceID());
            ready = true;
        }
    }
}

dLogger* SetupLogger(int zoneID, int instanceID) {
    std::string logPath = "./logs/WorldServer_" + std::to_string(zoneID) + "_" + std::to_string(instanceID) + "_" + std::to_string(time(nullptr)) + ".log";
    bool logToConsole = false;
    bool logDebugStatements = false;
#ifdef _DEBUG
    logToConsole = true;
    logDebugStatements = true;
#endif

    return new dLogger(logPath, logToConsole, logDebugStatements);
}

void HandlePacketChat(Packet* packet) {
    if (packet->data[0] == ID_DISCONNECTION_NOTIFICATION || packet->data[0] == ID_CONNECTION_LOST) {
        Game::logger->Log("WorldServer", "Lost our connection to chat, zone(%i), instance(%i)", Game::server->GetZoneID(), Game::server->GetInstanceID());

        chatConnected = false;
    }

    if (packet->data[0] == ID_CONNECTION_REQUEST_ACCEPTED) {
        Game::logger->Log("WorldServer", "Established connection to chat, zone(%i), instance (%i)", Game::server->GetZoneID(), Game::server->GetInstanceID());
        Game::chatSysAddr = packet->systemAddress;

        chatConnected = true;
    }

    if (packet->data[0] == ID_USER_PACKET_ENUM) {
        if (packet->data[1] == CHAT_INTERNAL) {
            switch (packet->data[3]) {
                case MSG_CHAT_INTERNAL_ROUTE_TO_PLAYER: {
                    CINSTREAM;
                    LWOOBJID playerID;
                    inStream.Read(playerID);
                    inStream.Read(playerID);

                    auto player = EntityManager::Instance()->GetEntity(playerID);
                    if (!player)
                        return;

                    auto sysAddr = player->GetSystemAddress();

                    //Write our stream outwards:
                    CBITSTREAM;
                    for (int i = 0; i < inStream.GetNumberOfBytesUsed(); i++) {
                        bitStream.Write(packet->data[i + 16]); //16 bytes == header + playerID to skip
                    }

                    SEND_PACKET; //send routed packet to player

                    break;
                }

                case MSG_CHAT_INTERNAL_ANNOUNCEMENT: {
                    CINSTREAM;
                    LWOOBJID header;
                    inStream.Read(header);

                    std::string title;
                    std::string msg;

                    uint32_t len;
                    inStream.Read<uint32_t>(len);
                    for (int i = 0; len > i; i++) {
                        char character;
                        inStream.Read<char>(character);
                        title += character;
                    }

                    len = 0;
                    inStream.Read<uint32_t>(len);
                    for (int i = 0; len > i; i++) {
                        char character;
                        inStream.Read<char>(character);
                        msg += character;
                    }

                    //Send to our clients:
                    AMFArrayValue args;
                    auto* titleValue = new AMFStringValue();
                    titleValue->SetStringValue(title.c_str());
                    auto* messageValue = new AMFStringValue();
                    messageValue->SetStringValue(msg.c_str());

                    args.InsertValue("title", titleValue);
                    args.InsertValue("message", messageValue);

                    GameMessages::SendUIMessageServerToAllClients("ToggleAnnounce", &args);

                    break;
                }

                case MSG_CHAT_INTERNAL_MUTE_UPDATE: {
                    CINSTREAM;
                    LWOOBJID playerId;
                    time_t expire = 0;
                    inStream.Read(playerId);
                    inStream.Read(playerId);
                    inStream.Read(expire);

                    auto* entity = EntityManager::Instance()->GetEntity(playerId);

                    if (entity != nullptr) {
                        entity->GetParentUser()->SetMuteExpire(expire);

                        entity->GetCharacter()->SendMuteNotice();
                    }

                    break;
                }

                case MSG_CHAT_INTERNAL_TEAM_UPDATE: {
                    CINSTREAM;
                    LWOOBJID header;
                    inStream.Read(header);

                    LWOOBJID teamID = 0;
                    char lootOption = 0;
                    char memberCount = 0;
                    std::vector<LWOOBJID> members;

                    inStream.Read(teamID);
                    bool deleteTeam = inStream.ReadBit();

                    if (deleteTeam) {
                        TeamManager::Instance()->DeleteTeam(teamID);

                        Game::logger->Log("WorldServer", "Deleting team (%llu)", teamID);

                        break;
                    }

                    inStream.Read(lootOption);
                    inStream.Read(memberCount);
                    Game::logger->Log("WorldServer", "Updating team (%llu), (%i), (%i)", teamID, lootOption, memberCount);
                    for (char i = 0; i < memberCount; i++) {
                        LWOOBJID member = LWOOBJID_EMPTY;
                        inStream.Read(member);
                        members.push_back(member);

                        Game::logger->Log("WorldServer", "Updating team member (%llu)", member);
                    }

                    TeamManager::Instance()->UpdateTeam(teamID, lootOption, members);

                    break;
                }

                default:
                    Game::logger->Log("WorldServer", "Received an unknown chat internal: %i", int(packet->data[3]));
            }
        }
    }
}

void HandlePacket(Packet* packet) {
    if (packet->data[0] == ID_DISCONNECTION_NOTIFICATION || packet->data[0] == ID_CONNECTION_LOST) {
        auto user = UserManager::Instance()->GetUser(packet->systemAddress);
        if (!user)
            return;

        auto c = user->GetLastUsedChar();
        if (!c) {
            UserManager::Instance()->DeleteUser(packet->systemAddress);
            return;
        }

        auto* entity = EntityManager::Instance()->GetEntity(c->GetObjectID());

        if (!entity) {
            entity = Player::GetPlayer(packet->systemAddress);
        }

        if (entity) {
            auto* skillComponent = entity->GetComponent<SkillComponent>();

            if (skillComponent != nullptr) {
                skillComponent->Reset();
            }

            entity->GetCharacter()->SaveXMLToDatabase();

            Game::logger->Log("WorldServer", "Deleting player %llu", entity->GetObjectID());

            EntityManager::Instance()->DestroyEntity(entity);
        }

        {
            CBITSTREAM;
            PacketUtils::WriteHeader(bitStream, CHAT_INTERNAL, MSG_CHAT_INTERNAL_PLAYER_REMOVED_NOTIFICATION);
            bitStream.Write(user->GetLoggedInChar());
            Game::chatServer->Send(&bitStream, SYSTEM_PRIORITY, RELIABLE, 0, Game::chatSysAddr, false);
        }

        UserManager::Instance()->DeleteUser(packet->systemAddress);

        if (PropertyManagementComponent::Instance() != nullptr) {
            PropertyManagementComponent::Instance()->Save();
        }

        CBITSTREAM;
        PacketUtils::WriteHeader(bitStream, MASTER, MSG_MASTER_PLAYER_REMOVED);
        bitStream.Write((LWOMAPID)Game::server->GetZoneID());
        bitStream.Write((LWOINSTANCEID)instanceID);
        Game::server->SendToMaster(&bitStream);
    }

    if (packet->data[0] != ID_USER_PACKET_ENUM)
        return;
    if (packet->data[1] == SERVER) {
        if (packet->data[3] == MSG_SERVER_VERSION_CONFIRM) {
            AuthPackets::HandleHandshake(Game::server, packet);
        }
    }

    if (packet->data[1] == MASTER) {
        switch (packet->data[3]) {
            case MSG_MASTER_REQUEST_PERSISTENT_ID_RESPONSE: {
                uint64_t requestID = PacketUtils::ReadPacketU64(8, packet);
                uint32_t objectID = PacketUtils::ReadPacketU32(16, packet);
                ObjectIDManager::Instance()->HandleRequestPersistentIDResponse(requestID, objectID);
                break;
            }

            case MSG_MASTER_REQUEST_ZONE_TRANSFER_RESPONSE: {
                uint64_t requestID = PacketUtils::ReadPacketU64(8, packet);
                ZoneInstanceManager::Instance()->HandleRequestZoneTransferResponse(requestID, packet);
                break;
            }

            case MSG_MASTER_SESSION_KEY_RESPONSE: {
                //Read our session key and to which user it belongs:
                RakNet::BitStream inStream(packet->data, packet->length, false);
                uint64_t header = inStream.Read(header);
                uint32_t sessionKey = 0;
                std::string username;

                inStream.Read(sessionKey);
                username = PacketUtils::ReadString(12, packet, false);

                //Find them:
                auto it = m_PendingUsers.find(username);
                if (it == m_PendingUsers.end())
                    return;

                //Convert our key:
                std::string userHash = std::to_string(sessionKey);
                userHash = md5(userHash);

                //Verify it:
                if (userHash != it->second.hash) {
                    Game::logger->Log("WorldServer", "SOMEONE IS TRYING TO HACK? SESSION KEY MISMATCH: ours: %s != master: %s", userHash.c_str(), it->second.hash.c_str());
                    Game::server->Disconnect(it->second.sysAddr, SERVER_DISCON_INVALID_SESSION_KEY);
                    return;
                } else {
                    Game::logger->Log("WorldServer", "User %s authenticated with correct key.", username.c_str());

                    UserManager::Instance()->DeleteUser(packet->systemAddress);

                    //Create our user and send them in:
                    UserManager::Instance()->CreateUser(it->second.sysAddr, username, userHash);

                    auto zone = dZoneManager::Instance()->GetZone();
                    if (zone) {
                        float x = 0.0f;
                        float y = 0.0f;
                        float z = 0.0f;

                        if (zone->GetZoneID().GetMapID() == 1100) {
                            auto pos = zone->GetSpawnPos();
                            x = pos.x;
                            y = pos.y;
                            z = pos.z;
                        }

                        WorldPackets::SendLoadStaticZone(it->second.sysAddr, x, y, z, zone->GetChecksum());
                    }

                    if (Game::server->GetZoneID() == 0) {
                        //Since doing this reroute breaks the client's request, we have to call this manually.
                        UserManager::Instance()->RequestCharacterList(it->second.sysAddr);
                    }

                    m_PendingUsers.erase(username);

                    //Notify master:
                    {
                        CBITSTREAM;
                        PacketUtils::WriteHeader(bitStream, MASTER, MSG_MASTER_PLAYER_ADDED);
                        bitStream.Write((LWOMAPID)Game::server->GetZoneID());
                        bitStream.Write((LWOINSTANCEID)instanceID);
                        Game::server->SendToMaster(&bitStream);
                    }
                }

                break;
            }
            case MSG_MASTER_AFFIRM_TRANSFER_REQUEST: {
                const uint64_t requestID = PacketUtils::ReadPacketU64(8, packet);

                Game::logger->Log("MasterServer", "Got affirmation request of transfer %llu", requestID);

                CBITSTREAM;

                PacketUtils::WriteHeader(bitStream, MASTER, MSG_MASTER_AFFIRM_TRANSFER_RESPONSE);
                bitStream.Write(requestID);
                Game::server->SendToMaster(&bitStream);

                break;
            }

            case MSG_MASTER_SHUTDOWN: {
                worldShutdownSequenceStarted = true;
                Game::logger->Log("WorldServer", "Got shutdown request from master, zone (%i), instance (%i)", Game::server->GetZoneID(), Game::server->GetInstanceID());
                break;
            }

            case MSG_MASTER_NEW_SESSION_ALERT: {
                RakNet::BitStream inStream(packet->data, packet->length, false);
                uint64_t header = inStream.Read(header);
                uint32_t sessionKey = inStream.Read(sessionKey);

                std::string username;

                uint32_t len;
                inStream.Read(len);

                for (int i = 0; i < len; i++) {
                    char character;
                    inStream.Read<char>(character);
                    username += character;
                }

                //Find them:
                User* user = UserManager::Instance()->GetUser(username.c_str());
                if (!user) {
                    Game::logger->Log("WorldServer", "Got new session alert for user %s, but they're not logged in.", username.c_str());
                    return;
                }

                //Check the key:
                if (sessionKey != std::atoi(user->GetSessionKey().c_str())) {
                    Game::logger->Log("WorldServer", "Got new session alert for user %s, but the session key is invalid.", username.c_str());
                    Game::server->Disconnect(user->GetSystemAddress(), SERVER_DISCON_INVALID_SESSION_KEY);
                    return;
                }
                break;
            }

            default:
                Game::logger->Log("WorldServer", "Unknown packet ID from master %i", int(packet->data[3]));
        }

        return;
    }

    if (packet->data[1] != WORLD)
        return;

    switch (packet->data[3]) {
        case MSG_WORLD_CLIENT_VALIDATION: {
            std::string username = PacketUtils::ReadString(0x08, packet, true);
            std::string sessionKey = PacketUtils::ReadString(74, packet, true);
            std::string clientDatabaseChecksum = PacketUtils::ReadString(packet->length - 33, packet, false);

            // sometimes client puts a null terminator at the end of the checksum and sometimes doesn't, weird
            clientDatabaseChecksum = clientDatabaseChecksum.substr(0, 32);

            // If the check is turned on, validate the client's database checksum.
            if (Game::config->GetValue("check_fdb") == "1" && !databaseChecksum.empty()) {
                uint32_t gmLevel = 0;
                auto* stmt = Database::CreatePreppedStmt("SELECT gm_level FROM accounts WHERE name=? LIMIT 1;");
                stmt->setString(1, username.c_str());

                auto* res = stmt->executeQuery();
                while (res->next()) {
                    gmLevel = res->getInt(1);
                }

                delete stmt;
                delete res;

                // Developers may skip this check
                if (gmLevel < 8 && clientDatabaseChecksum != databaseChecksum) {
                    Game::logger->Log("WorldServer", "Client's database checksum does not match the server's, aborting connection.");
                    Game::server->Disconnect(packet->systemAddress, SERVER_DISCON_KICK);
                    return;
                }
            }

            //Request the session info from Master:
            CBITSTREAM;
            PacketUtils::WriteHeader(bitStream, MASTER, MSG_MASTER_REQUEST_SESSION_KEY);
            PacketUtils::WriteString(bitStream, username, 64);
            Game::server->SendToMaster(&bitStream);

            //Insert info into our pending list
            tempSessionInfo info;
            info.sysAddr = SystemAddress(packet->systemAddress);
            info.hash = sessionKey;
            m_PendingUsers.insert(std::make_pair(username, info));

            break;
        }

        case MSG_WORLD_CLIENT_CHARACTER_LIST_REQUEST: {
            //We need to delete the entity first, otherwise the char list could delete it while it exists in the world!
            if (Game::server->GetZoneID() != 0) {
                auto user = UserManager::Instance()->GetUser(packet->systemAddress);
                if (!user)
                    return;
                EntityManager::Instance()->DestroyEntity(user->GetLastUsedChar()->GetEntity());
            }

            //This loops prevents users who aren't authenticated to double-request the char list, which
            //would make the login screen freeze sometimes.
            if (m_PendingUsers.size() > 0) {
                for (auto it : m_PendingUsers) {
                    if (it.second.sysAddr == packet->systemAddress) {
                        return;
                    }
                }
            }

            UserManager::Instance()->RequestCharacterList(packet->systemAddress);
            break;
        }

        case MSG_WORLD_CLIENT_GAME_MSG: {
            RakNet::BitStream bitStream(packet->data, packet->length, false);

            uint64_t header;
            LWOOBJID objectID;
            uint16_t messageID;

            bitStream.Read(header);
            bitStream.Read(objectID);
            bitStream.Read(messageID);

            RakNet::BitStream dataStream;
            bitStream.Read(dataStream, bitStream.GetNumberOfUnreadBits());

            GameMessageHandler::HandleMessage(&dataStream, packet->systemAddress, objectID, GAME_MSG(messageID));
            break;
        }

        case MSG_WORLD_CLIENT_CHARACTER_CREATE_REQUEST: {
            UserManager::Instance()->CreateCharacter(packet->systemAddress, packet);
            break;
        }

        case MSG_WORLD_CLIENT_LOGIN_REQUEST: {
            RakNet::BitStream inStream(packet->data, packet->length, false);
            uint64_t header = inStream.Read(header);

            LWOOBJID playerID = 0;
            inStream.Read(playerID);
            playerID = GeneralUtils::ClearBit(playerID, OBJECT_BIT_CHARACTER);
            playerID = GeneralUtils::ClearBit(playerID, OBJECT_BIT_PERSISTENT);

            auto user = UserManager::Instance()->GetUser(packet->systemAddress);

            if (user) {
                auto lastCharacter = user->GetLoggedInChar();
                // This means we swapped characters and we need to remove the previous player from the container.
                if (static_cast<uint32_t>(lastCharacter) != playerID) {
                    CBITSTREAM;
                    PacketUtils::WriteHeader(bitStream, CHAT_INTERNAL, MSG_CHAT_INTERNAL_PLAYER_REMOVED_NOTIFICATION);
                    bitStream.Write(lastCharacter);
                    Game::chatServer->Send(&bitStream, SYSTEM_PRIORITY, RELIABLE, 0, Game::chatSysAddr, false);
                }
            }

            UserManager::Instance()->LoginCharacter(packet->systemAddress, static_cast<uint32_t>(playerID));
            break;
        }

        case MSG_WORLD_CLIENT_CHARACTER_DELETE_REQUEST: {
            UserManager::Instance()->DeleteCharacter(packet->systemAddress, packet);
            UserManager::Instance()->RequestCharacterList(packet->systemAddress);
            break;
        }

        case MSG_WORLD_CLIENT_CHARACTER_RENAME_REQUEST: {
            UserManager::Instance()->RenameCharacter(packet->systemAddress, packet);
            break;
        }

        case MSG_WORLD_CLIENT_LEVEL_LOAD_COMPLETE: {
            Game::logger->Log("WorldServer", "Received level load complete from user.");
            User* user = UserManager::Instance()->GetUser(packet->systemAddress);
            if (user) {
                Character* c = user->GetLastUsedChar();
                if (c != nullptr) {
                    std::u16string username = GeneralUtils::ASCIIToUTF16(c->GetName());
                    Game::server->GetReplicaManager()->AddParticipant(packet->systemAddress);

                    EntityInfo info{};
                    info.lot = 1;
                    Entity* player = EntityManager::Instance()->CreateEntity(info, UserManager::Instance()->GetUser(packet->systemAddress));

                    WorldPackets::SendCreateCharacter(packet->systemAddress, player, c->GetXMLData(), username, c->GetGMLevel());
                    WorldPackets::SendServerState(packet->systemAddress);

                    const auto respawnPoint = player->GetCharacter()->GetRespawnPoint(dZoneManager::Instance()->GetZone()->GetWorldID());

                    EntityManager::Instance()->ConstructEntity(player, UNASSIGNED_SYSTEM_ADDRESS, true);

                    if (respawnPoint != NiPoint3::ZERO) {
                        GameMessages::SendPlayerReachedRespawnCheckpoint(player, respawnPoint, NiQuaternion::IDENTITY);
                    }

                    EntityManager::Instance()->ConstructAllEntities(packet->systemAddress);

                    auto* characterComponent = player->GetComponent<CharacterComponent>();
                    if (characterComponent) {
                        player->GetComponent<CharacterComponent>()->RocketUnEquip(player);
                    }

                    c->SetRetroactiveFlags();

                    player->RetroactiveVaultSize();

                    player->GetCharacter()->SetTargetScene("");

                    // Fix the destroyable component
                    auto* destroyableComponent = player->GetComponent<DestroyableComponent>();

                    if (destroyableComponent != nullptr) {
                        destroyableComponent->FixStats();
                    }

                    //Tell the player to generate BBB models, if any:
                    if (g_CloneID != 0) {
                        const auto& worldId = dZoneManager::Instance()->GetZone()->GetZoneID();

                        const auto zoneId = Game::server->GetZoneID();
                        const auto cloneId = g_CloneID;

                        auto query = CDClientDatabase::CreatePreppedStmt(
                            "SELECT id FROM PropertyTemplate WHERE mapID = ?;");
                        query.bind(1, (int)zoneId);

                        auto result = query.execQuery();

                        if (result.eof() || result.fieldIsNull(0)) {
                            Game::logger->Log("WorldServer", "No property templates found for zone %d, not sending BBB", zoneId);
                            goto noBBB;
                        }

                        //Check for BBB models:
                        auto stmt = Database::CreatePreppedStmt("SELECT ugc_id FROM properties_contents WHERE lot=14 AND property_id=?");

                        int templateId = result.getIntField(0);

                        result.finalize();

                        auto* propertyLookup = Database::CreatePreppedStmt("SELECT * FROM properties WHERE template_id = ? AND clone_id = ?;");

                        propertyLookup->setInt(1, templateId);
                        propertyLookup->setInt64(2, g_CloneID);

                        auto* propertyEntry = propertyLookup->executeQuery();
                        uint64_t propertyId = 0;

                        if (propertyEntry->next()) {
                            propertyId = propertyEntry->getUInt64(1);
                        }

                        delete propertyLookup;

                        stmt->setUInt64(1, propertyId);
                        auto res = stmt->executeQuery();
                        while (res->next()) {
                            Game::logger->Log("UGC", "Getting lxfml ugcID: %u", res->getUInt(1));

                            //Get lxfml:
                            auto stmtL = Database::CreatePreppedStmt("SELECT lxfml from ugc where id=?");
                            stmtL->setUInt(1, res->getUInt(1));

                            auto lxres = stmtL->executeQuery();

                            while (lxres->next()) {
                                auto lxfml = lxres->getBlob(1);

                                lxfml->seekg(0, std::ios::end);
                                size_t lxfmlSize = lxfml->tellg();
                                lxfml->seekg(0);

                                //Send message:
                                {
                                    LWOOBJID blueprintID = res->getUInt(1);
                                    blueprintID = GeneralUtils::SetBit(blueprintID, OBJECT_BIT_CHARACTER);
                                    blueprintID = GeneralUtils::SetBit(blueprintID, OBJECT_BIT_PERSISTENT);

                                    CBITSTREAM;
                                    PacketUtils::WriteHeader(bitStream, CLIENT, MSG_CLIENT_BLUEPRINT_SAVE_RESPONSE);
                                    bitStream.Write<LWOOBJID>(0); //always zero so that a check on the client passes
                                    bitStream.Write<unsigned int>(0);
                                    bitStream.Write<unsigned int>(1);
                                    bitStream.Write(blueprintID);

                                    bitStream.Write<uint32_t>(lxfmlSize);

                                    for (size_t i = 0; i < lxfmlSize; ++i)
                                        bitStream.Write<uint8_t>(lxfml->get());

                                    SystemAddress sysAddr = packet->systemAddress;
                                    SEND_PACKET;
                                    PacketUtils::SavePacket("lxfml packet " + std::to_string(res->getUInt(1)) + ".bin", (char*)bitStream.GetData(), bitStream.GetNumberOfBytesUsed());
                                }
                            }

                            delete stmtL;
                            delete lxres;
                        }

                        delete stmt;
                        delete res;
                    }

                noBBB:

                    // Tell the client it's done loading:
                    GameMessages::SendInvalidZoneTransferList(player, packet->systemAddress, GeneralUtils::ASCIIToUTF16(Game::config->GetValue("source")), u"", false, false);
                    GameMessages::SendServerDoneLoadingAllObjects(player, packet->systemAddress);

                    //Send the player it's mail count:
                    //update: this might not be needed so im going to try disabling this here.
                    //Mail::HandleNotificationRequest(packet->systemAddress, player->GetObjectID());

                    //Notify chat that a player has loaded:
                    {
                        const auto& playerName = player->GetCharacter()->GetName();
                        //RakNet::RakString playerName(player->GetCharacter()->GetName().c_str());

                        CBITSTREAM;
                        PacketUtils::WriteHeader(bitStream, CHAT_INTERNAL, MSG_CHAT_INTERNAL_PLAYER_ADDED_NOTIFICATION);
                        bitStream.Write(player->GetObjectID());
                        bitStream.Write<uint32_t>(playerName.size());
                        for (size_t i = 0; i < playerName.size(); i++) {
                            bitStream.Write(playerName[i]);
                        }

                        auto zone = dZoneManager::Instance()->GetZone()->GetZoneID();
                        bitStream.Write(zone.GetMapID());
                        bitStream.Write(zone.GetInstanceID());
                        bitStream.Write(zone.GetCloneID());
                        bitStream.Write(player->GetParentUser()->GetMuteExpire());

                        Game::chatServer->Send(&bitStream, SYSTEM_PRIORITY, RELIABLE, 0, Game::chatSysAddr, false);
                    }
                } else {
                    Game::logger->Log("WorldServer", "Couldn't find character to log in with for user %s (%i)!", user->GetUsername().c_str(), user->GetAccountID());
                    Game::server->Disconnect(packet->systemAddress, SERVER_DISCON_CHARACTER_NOT_FOUND);
                }
            } else {
                Game::logger->Log("WorldServer", "Couldn't get user for level load complete!");
            }
            break;
        }

        case MSG_WORLD_CLIENT_POSITION_UPDATE: {
            ClientPackets::HandleClientPositionUpdate(packet->systemAddress, packet);
            break;
        }

        case MSG_WORLD_CLIENT_MAIL: {
            RakNet::BitStream bitStream(packet->data, packet->length, false);
            LWOOBJID space;
            bitStream.Read(space);
            Mail::HandleMailStuff(&bitStream, packet->systemAddress, UserManager::Instance()->GetUser(packet->systemAddress)->GetLastUsedChar()->GetEntity());
            break;
        }

        case MSG_WORLD_CLIENT_ROUTE_PACKET: {
            //Yeet to chat
            CINSTREAM;
            uint64_t header = 0;
            uint32_t size = 0;
            inStream.Read(header);
            inStream.Read(size);

            if (size > 20000) {
                Game::logger->Log("WorldServer", "Tried to route a packet with a read size > 20000, so likely a false packet.");
                return;
            }

            CBITSTREAM;

            PacketUtils::WriteHeader(bitStream, CHAT, packet->data[14]);

            //We need to insert the player's objectID so the chat server can find who originated this request:
            LWOOBJID objectID = 0;
            auto user = UserManager::Instance()->GetUser(packet->systemAddress);
            if (user) {
                objectID = user->GetLastUsedChar()->GetObjectID();
            }

            bitStream.Write(objectID);

            //Now write the rest of the data:
            auto data = inStream.GetData();
            for (uint32_t i = 0; i < size; ++i) {
                bitStream.Write(data[i + 23]);
            }

            Game::chatServer->Send(&bitStream, SYSTEM_PRIORITY, RELIABLE_ORDERED, 0, Game::chatSysAddr, false);
            break;
        }

        case MSG_WORLD_CLIENT_STRING_CHECK: {
            ClientPackets::HandleChatModerationRequest(packet->systemAddress, packet);
            break;
        }

        case MSG_WORLD_CLIENT_GENERAL_CHAT_MESSAGE: {
            if (chatDisabled) {
                ChatPackets::SendMessageFail(packet->systemAddress);
            } else {
                ClientPackets::HandleChatMessage(packet->systemAddress, packet);
            }

            break;
        }

        case MSG_WORLD_CLIENT_HANDLE_FUNNESS: {
            //This means the client is running slower or faster than it should.
            //Could be insane lag, but I'mma just YEET them as it's usually speedhacking.
            //This is updated to now count the amount of times we've been caught "speedhacking" to kick with a delay
            //This is hopefully going to fix the random disconnects people face sometimes.
            if (Game::config->GetValue("disable_anti_speedhack") == "1") {
                return;
            }

            User* user = UserManager::Instance()->GetUser(packet->systemAddress);
            if (user) {
                user->UserOutOfSync();
            } else {
                Game::server->Disconnect(packet->systemAddress, SERVER_DISCON_KICK);
            }
            break;
        }

        default:
            Game::server->GetLogger()->Log("HandlePacket", "Unknown world packet received: %i", int(packet->data[3]));
    }
}

void WorldShutdownProcess(uint32_t zoneId) {
    Game::logger->Log("WorldServer", "Saving map %i instance %i", zoneId, instanceID);
    for (auto i = 0; i < Game::server->GetReplicaManager()->GetParticipantCount(); ++i) {
        const auto& player = Game::server->GetReplicaManager()->GetParticipantAtIndex(i);

        auto* entity = Player::GetPlayer(player);
        Game::logger->Log("WorldServer", "Saving data!");
        if (entity != nullptr && entity->GetCharacter() != nullptr) {
            auto* skillComponent = entity->GetComponent<SkillComponent>();

            if (skillComponent != nullptr) {
                skillComponent->Reset();
            }
            Game::logger->Log("WorldServer", "Saving character %s...", entity->GetCharacter()->GetName().c_str());
            entity->GetCharacter()->SaveXMLToDatabase();
            Game::logger->Log("WorldServer", "Character data for %s was saved!", entity->GetCharacter()->GetName().c_str());
        }
    }

    if (PropertyManagementComponent::Instance() != nullptr) {
        Game::logger->Log("WorldServer", "Saving ALL property data for zone %i clone %i!", zoneId, PropertyManagementComponent::Instance()->GetCloneId());
        PropertyManagementComponent::Instance()->Save();
        Game::logger->Log("WorldServer", "ALL property data saved for zone %i clone %i!", zoneId, PropertyManagementComponent::Instance()->GetCloneId());
    }

    Game::logger->Log("WorldServer", "ALL DATA HAS BEEN SAVED FOR ZONE %i INSTANCE %i!", zoneId, instanceID);

    while (Game::server->GetReplicaManager()->GetParticipantCount() > 0) {
        const auto& player = Game::server->GetReplicaManager()->GetParticipantAtIndex(0);

        Game::server->Disconnect(player, SERVER_DISCON_KICK);
    }
    SendShutdownMessageToMaster();
}

void WorldShutdownSequence() {
    if (worldShutdownSequenceStarted || worldShutdownSequenceComplete) {
        return;
    }

    worldShutdownSequenceStarted = true;

    Game::logger->Log("WorldServer", "Zone (%i) instance (%i) shutting down outside of main loop!", Game::server->GetZoneID(), instanceID);
    WorldShutdownProcess(Game::server->GetZoneID());
    FinalizeShutdown();
}

void FinalizeShutdown() {
    //Delete our objects here:
    if (Game::physicsWorld)
        Game::physicsWorld = nullptr;
    if (Game::zoneManager)
        delete Game::zoneManager;

    Game::logger->Log("WorldServer", "Shutdown complete, zone (%i), instance (%i)", Game::server->GetZoneID(), instanceID);

    Metrics::Clear();
    Database::Destroy("WorldServer");
    delete Game::chatFilter;
    delete Game::server;
    delete Game::logger;

    worldShutdownSequenceComplete = true;

    exit(EXIT_SUCCESS);
}

void SendShutdownMessageToMaster() {
    CBITSTREAM;
    PacketUtils::WriteHeader(bitStream, MASTER, MSG_MASTER_SHUTDOWN_RESPONSE);
    Game::server->SendToMaster(&bitStream);
}
