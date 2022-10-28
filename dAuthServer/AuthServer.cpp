#include <chrono>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>

//DLU Includes:
#include "Database.h"
#include "Diagnostics.h"
#include "dCommonVars.h"
#include "dConfig.h"
#include "dLogger.h"
#include "dServer.h"

//RakNet includes:
#include "RakNetDefines.h"

//Auth includes:
#include "AuthPackets.h"
#include "Game.h"
#include "dMessageIdentifiers.h"
namespace Game {
dLogger* logger;
dServer* server;
dConfig* config;
} // namespace Game

dLogger* SetupLogger();
void HandlePacket(Packet* packet);

namespace AuthServer {
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
}

int framesSinceLastSQLPing = 0;
int framesSinceLastFlush = 0;
int framesSinceMasterDisconnect = 0;

int main(int argc, char** argv) {
    AuthServer::prepareDiagnostics(argv);
    Game::logger = SetupLogger();
    if (!Game::logger)
        return 0;
	AuthServer::printServerDetails();
    if (AuthServer::prepareServer() == 0) return 0;
    //Run it until server gets a kill message from Master:
    auto t = std::chrono::high_resolution_clock::now();
    while (true) {
        if (AuthServer::checkConnectionToMaster() == 0)
            break;
        AuthServer::handleServerPackets();
        AuthServer::flushServerLogs();
        AuthServer::keepDatabaseConnectionAlive();
        //Sleep our thread since auth can afford to.
        t += std::chrono::milliseconds(mediumFramerate); //Auth can run at a lower "fps"
        std::this_thread::sleep_until(t);
    }
    //Delete our objects here:
    AuthServer::destroyOnExit();
    exit(EXIT_SUCCESS);
    return EXIT_SUCCESS;
	}

/**
	* @brief Flush server logs every 30 seconds
*/
void AuthServer::flushServerLogs() {
    if (framesSinceLastFlush < 900) {
		framesSinceLastFlush++;
		return;
    }
    Game::logger->Flush();
    framesSinceLastFlush = 0;   
}

/**
	* @brief Prepare the server
	* @return 0 if the configuration failed, 1 otherwise
*/
int AuthServer::prepareServer() {
	dConfig config("authconfig.ini");
	setGameConfigs(&config);
	if (connectToDatabase(&config) == 0)
		return 0;

	getServerAddressAndConnect(&config);
	return 1;
}

/**
	* @brief Check the connection to Master
*/
int AuthServer::checkConnectionToMaster() {
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
	* Prepare server diagnostics
*/
void AuthServer::prepareDiagnostics(char** argv) {
	Diagnostics::SetProcessName("Auth");
	Diagnostics::SetProcessFileName(argv[0]);
	Diagnostics::Initialize();
}

/**
	* Print some details about the server
*/
void AuthServer::printServerDetails() {
	Game::logger->Log("AuthServer", "Starting Auth server...");
	Game::logger->Log("AuthServer", "Version: %i.%i", PROJECT_VERSION_MAJOR, PROJECT_VERSION_MINOR);
	Game::logger->Log("AuthServer", "Compiled on: %s", __TIMESTAMP__);
}

/**
	* @brief Prepare game configs
*/
void AuthServer::setGameConfigs(dConfig* configPointer) {
    Game::config = configPointer;
    dConfig config = *configPointer;
	Game::logger->SetLogToConsole(bool(std::stoi(config.GetValue("log_to_console"))));
	Game::logger->SetLogDebugStatements(config.GetValue("log_debug_statements") == "1");
}

/**
	* @brief Gets the server's IP and creates the server
	* @param config - the server configurations
*/
void AuthServer::getServerAddressAndConnect(dConfig* config) {
	//Find out the master's IP:
	std::string masterIP;
	int masterPort = 1500;
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
void AuthServer::createServer(dConfig* configPointer, std::string masterIP, int masterPort) {
    dConfig config = *configPointer;
	//It's safe to pass 'localhost' here, as the IP is only used as the external IP.
	int maxClients = 50;
	int ourPort = 1001; //LU client is hardcoded to use this for auth port, so I'm making it the default.
	if (config.GetValue("max_clients") != "")
		maxClients = std::stoi(config.GetValue("max_clients"));
	if (config.GetValue("port") != "")
		ourPort = std::atoi(config.GetValue("port").c_str());

	Game::server = new dServer(config.GetValue("external_ip"), ourPort, 0, maxClients, false, true, Game::logger, masterIP, masterPort, ServerType::Auth);
}

/**
	* @brief Connect to MySQL Database
	* @param config - game configurations
	* @return 1 if the connection succeeded, else 0
*/
int AuthServer::connectToDatabase(dConfig* configPointer) {
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
		Game::logger->Log("AuthServer", "Got an error while connecting to the database: %s", ex.what());
		Database::Destroy("AuthServer");
		delete Game::server;
		delete Game::logger;
		return 0;
	}
}

/**
	* Keep database connection alive by pinging it every 10 minutes
*/
void AuthServer::keepDatabaseConnectionAlive() {
	if (framesSinceLastSQLPing < 40000) {
		framesSinceLastSQLPing++;
		return;
	}
	pingDatabase();
	framesSinceLastSQLPing = 0;
}

void AuthServer::pingDatabase() {
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
void AuthServer::handleServerPackets() {
Packet* packet = nullptr;
Game::server->ReceiveFromMaster(); //ReceiveFromMaster also handles the master packets if needed.
packet = Game::server->Receive();
if (packet) {
    HandlePacket(packet);
    Game::server->DeallocatePacket(packet);
    packet = nullptr;
}
}

void AuthServer::destroyOnExit() {
	Database::Destroy("AuthServer");
	delete Game::server;
	delete Game::logger;
}

dLogger* SetupLogger() {
    std::string logPath = "./logs/AuthServer_" + std::to_string(time(nullptr)) + ".log";
    bool logToConsole = false;
    bool logDebugStatements = false;
#ifdef _DEBUG
    logToConsole = true;
    logDebugStatements = true;
#endif

    return new dLogger(logPath, logToConsole, logDebugStatements);
}

void HandlePacket(Packet* packet) {
    if (packet->data[0] == ID_USER_PACKET_ENUM) {
        if (packet->data[1] == SERVER) {
            if (packet->data[3] == MSG_SERVER_VERSION_CONFIRM) {
                AuthPackets::HandleHandshake(Game::server, packet);
            }
        } else if (packet->data[1] == AUTH) {
            if (packet->data[3] == MSG_AUTH_LOGIN_REQUEST) {
                AuthPackets::HandleLoginRequest(Game::server, packet);
            }
        }
    }
}
