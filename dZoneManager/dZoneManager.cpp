#include "Game.h"
#include "dCommonVars.h"
#include "dZoneManager.h"
#include "EntityManager.h"
#include "Logger.h"
#include "dConfig.h"
#include "InventoryComponent.h"
#include "DestroyableComponent.h"
#include "GameMessages.h"
#include "VanityUtilities.h"
#include "WorldConfig.h"
#include "CDZoneTableTable.h"
#include <chrono>
#include "eObjectBits.h"
#include "CDZoneTableTable.h"
#include "AssetManager.h"
#include <ranges>

#include "ObjectIDManager.h"

void dZoneManager::Initialize(const LWOZONEID& zoneID) {
	LOG("Preparing zone: %i/%i/%i", zoneID.GetMapID(), zoneID.GetInstanceID(), zoneID.GetCloneID());

	int64_t startTime = 0;
	int64_t endTime = 0;

	startTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();

	LoadZone(zoneID);

	LOT zoneControlTemplate = 2365;

	const CDZoneTable* zone = CDZoneTableTable::Query(zoneID.GetMapID());

	if (zone != nullptr) {
		zoneControlTemplate = zone->zoneControlTemplate != -1 ? zone->zoneControlTemplate : 2365;
		const auto min = zone->ghostdistance_min != -1.0f ? zone->ghostdistance_min : 100;
		const auto max = zone->ghostdistance != -1.0f ? zone->ghostdistance : 100;
		Game::entityManager->SetGhostDistanceMax(max + min);
		Game::entityManager->SetGhostDistanceMin(max);
		m_PlayerLoseCoinsOnDeath = zone->PlayerLoseCoinsOnDeath;
		m_DisableSaveLocation = zone->disableSaveLoc;
		m_MountsAllowed = zone->mountsAllowed;
		m_PetsAllowed = zone->petsAllowed;
	}

	LOG("Creating zone control object %i", zoneControlTemplate);

	// Create ZoneControl object
	if (!Game::entityManager) {
		LOG("ERROR: No entity manager loaded. Cannot proceed.");
		throw std::invalid_argument("No entity manager loaded. Cannot proceed.");
	}
	Game::entityManager->Initialize();
	EntityInfo info;
	info.lot = zoneControlTemplate;

	/* Yep its hardcoded like this in the client too, this exact value. */
	info.id = 0x3FFF'FFFFFFFELL;
	Entity* zoneControl = Game::entityManager->CreateEntity(info, nullptr, nullptr, true);
	m_ZoneControlObject = zoneControl;

	m_pZone->Initalize();

	endTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();

	LoadWorldConfig();

	LOG("Zone prepared in: %llu ms", (endTime - startTime));

	VanityUtilities::SpawnVanity();
}

dZoneManager::~dZoneManager() {
	if (m_pZone) delete m_pZone;

	for (auto* spawner : m_Spawners | std::views::values) {
		if (spawner) {
			delete spawner;
			spawner = nullptr;
		}
	}
}

Zone* dZoneManager::GetZoneMut() const {
	DluAssert(m_pZone);
	return m_pZone;
}

void dZoneManager::LoadZone(const LWOZONEID& zoneID) {
	if (m_pZone) delete m_pZone;

	m_ZoneID = zoneID;
	m_pZone = new Zone(zoneID);
}

void dZoneManager::AddSpawner(LWOOBJID id, Spawner* spawner) {
	m_Spawners[id] = spawner;
}

const LWOZONEID& dZoneManager::GetZoneID() const {
	return m_ZoneID;
}

void dZoneManager::Update(float deltaTime) {
	for (auto spawner : m_Spawners | std::views::values) {
		spawner->Update(deltaTime);
	}
}

LWOOBJID dZoneManager::MakeSpawner(SpawnerInfo info) {
	auto objectId = info.spawnerID;

	if (objectId == LWOOBJID_EMPTY) {
		objectId = ObjectIDManager::GenerateObjectID();
		GeneralUtils::SetBit(objectId, eObjectBits::CLIENT);

		info.spawnerID = objectId;
	}

	auto* spawner = new Spawner(info);

	EntityInfo entityInfo{};

	entityInfo.id = objectId;
	entityInfo.lot = 176;

	auto* entity = Game::entityManager->CreateEntity(entityInfo, nullptr, nullptr, false, objectId);

	Game::entityManager->ConstructEntity(entity);

	AddSpawner(objectId, spawner);

	return objectId;
}

Spawner* dZoneManager::GetSpawner(const LWOOBJID id) {
	const auto& index = m_Spawners.find(id);
	return index != m_Spawners.end() ? index->second : nullptr;
}

void dZoneManager::RemoveSpawner(const LWOOBJID id) {
	auto* spawner = GetSpawner(id);

	if (spawner == nullptr) {
		LOG("Failed to find spawner (%llu)", id);
		return;
	}

	auto* entity = Game::entityManager->GetEntity(id);

	LOG("Destroying spawner (%llu)", id);

	if (entity != nullptr) {
		entity->Kill();
	} else {
		LOG("Failed to find spawner entity (%llu)", id);
	}

	spawner->DestroyAllEntities();

	spawner->Deactivate();

	LOG("Destroyed spawner (%llu)", id);

	m_Spawners.erase(id);

	delete spawner;
}


std::vector<Spawner*> dZoneManager::GetSpawnersByName(const std::string& spawnerName) {
	std::vector<Spawner*> spawners;
	for (const auto& spawner : m_Spawners | std::views::values) {
		if (spawner->GetName() == spawnerName) {
			spawners.push_back(spawner);
		}
	}

	return spawners;
}

std::vector<Spawner*> dZoneManager::GetSpawnersInGroup(const std::string& group) {
	std::vector<Spawner*> spawnersInGroup;
	for (auto spawner : m_Spawners | std::views::values) {
		const auto& groups = spawner->m_Info.groups;
		if (std::ranges::find(groups, group) != groups.end()) {
			spawnersInGroup.push_back(spawner);
		}
	}

	return spawnersInGroup;
}

uint32_t dZoneManager::GetUniqueMissionIdStartingValue() {
	if (m_UniqueMissionIdStart == 0) {
		auto tableData = CDClientDatabase::ExecuteQuery("SELECT COUNT(*) FROM Missions WHERE isMission = 0 GROUP BY isMission;");
		m_UniqueMissionIdStart = tableData.getIntField(0, 1);
	}
	return m_UniqueMissionIdStart;
}

bool dZoneManager::CheckIfAccessibleZone(LWOMAPID zoneID) {
	const CDZoneTable* zone = CDZoneTableTable::Query(zoneID);
	return zone && Game::assetManager->HasFile("maps/" + zone->zoneName);
}

void dZoneManager::LoadWorldConfig() {
	// Already loaded
	if (m_WorldConfig) return;

	LOG_DEBUG("Loading WorldConfig into memory");

	// This table only has 1 row and only should have 1 row.
	auto worldConfig = CDClientDatabase::ExecuteQuery("SELECT * FROM WorldConfig LIMIT 1;");

	m_WorldConfig = WorldConfig();

	if (worldConfig.eof()) {
		LOG("WorldConfig table is empty. Is this intended?");
		return;
	}

	// Now read in the giant table
	m_WorldConfig->peGravityValue = worldConfig.getFloatField("pegravityvalue");
	m_WorldConfig->peBroadphaseWorldSize = worldConfig.getFloatField("pebroadphaseworldsize");
	m_WorldConfig->peGameObjScaleFactor = worldConfig.getFloatField("pegameobjscalefactor");

	m_WorldConfig->characterRotationSpeed = worldConfig.getFloatField("character_rotation_speed");

	m_WorldConfig->characterWalkForwardSpeed = worldConfig.getFloatField("character_walk_forward_speed");
	m_WorldConfig->characterWalkBackwardSpeed = worldConfig.getFloatField("character_walk_backward_speed");
	m_WorldConfig->characterWalkStrafeSpeed = worldConfig.getFloatField("character_walk_strafe_speed");
	m_WorldConfig->characterWalkStrafeForwardSpeed = worldConfig.getFloatField("character_walk_strafe_forward_speed");
	m_WorldConfig->characterWalkStrafeBackwardSpeed = worldConfig.getFloatField("character_walk_strafe_backward_speed");

	m_WorldConfig->characterRunBackwardSpeed = worldConfig.getFloatField("character_run_backward_speed");
	m_WorldConfig->characterRunStrafeSpeed = worldConfig.getFloatField("character_run_strafe_speed");
	m_WorldConfig->characterRunStrafeForwardSpeed = worldConfig.getFloatField("character_run_strafe_forward_speed");
	m_WorldConfig->characterRunStrafeBackwardSpeed = worldConfig.getFloatField("character_run_strafe_backward_speed");

	m_WorldConfig->characterGroundedTime = worldConfig.getFloatField("characterGroundedTime");
	m_WorldConfig->characterGroundedSpeed = worldConfig.getFloatField("characterGroundedSpeed");

	m_WorldConfig->characterVersion = worldConfig.getIntField("CharacterVersion");
	m_WorldConfig->characterEyeHeight = worldConfig.getFloatField("character_eye_height");
	m_WorldConfig->characterMaxSlope = worldConfig.getFloatField("character_max_slope");

	m_WorldConfig->globalCooldown = worldConfig.getFloatField("global_cooldown");
	m_WorldConfig->globalImmunityTime = worldConfig.getFloatField("globalImmunityTime");

	m_WorldConfig->defaultRespawnTime = worldConfig.getFloatField("defaultrespawntime");
	m_WorldConfig->missionTooltipTimeout = worldConfig.getFloatField("mission_tooltip_timeout");
	m_WorldConfig->vendorBuyMultiplier = worldConfig.getFloatField("vendor_buy_multiplier", 0.1);
	m_WorldConfig->petFollowRadius = worldConfig.getFloatField("pet_follow_radius");

	m_WorldConfig->flightVerticalVelocity = worldConfig.getFloatField("flight_vertical_velocity");
	m_WorldConfig->flightAirspeed = worldConfig.getFloatField("flight_airspeed");
	m_WorldConfig->flightFuelRatio = worldConfig.getFloatField("flight_fuel_ratio");
	m_WorldConfig->flightMaxAirspeed = worldConfig.getFloatField("flight_max_airspeed");

	m_WorldConfig->defaultHomespaceTemplate = worldConfig.getIntField("defaultHomespaceTemplate");

	m_WorldConfig->coinsLostOnDeathPercent = worldConfig.getFloatField("coins_lost_on_death_percent");
	m_WorldConfig->coinsLostOnDeathMin = worldConfig.getIntField("coins_lost_on_death_min");
	m_WorldConfig->coinsLostOnDeathMax = worldConfig.getIntField("coins_lost_on_death_max");
	m_WorldConfig->coinsLostOnDeathMinTimeout = worldConfig.getFloatField("coins_lost_on_death_min_timeout");
	m_WorldConfig->coinsLostOnDeathMaxTimeout = worldConfig.getFloatField("coins_lost_on_death_max_timeout");

	m_WorldConfig->characterVotesPerDay = worldConfig.getIntField("character_votes_per_day");

	m_WorldConfig->defaultPropertyMaxHeight = worldConfig.getFloatField("defaultPropertyMaxHeight");
	m_WorldConfig->propertyCloneLimit = worldConfig.getIntField("nPropertyCloneLimit");
	m_WorldConfig->propertyReputationDelay = worldConfig.getIntField("propertyReputationDelay");
	m_WorldConfig->propertyModerationRequestApprovalCost = worldConfig.getIntField("property_moderation_request_approval_cost");
	m_WorldConfig->propertyModerationRequestReviewCost = worldConfig.getIntField("property_moderation_request_review_cost");
	m_WorldConfig->propertyModRequestsAllowedSpike = worldConfig.getIntField("propertyModRequestsAllowedSpike");
	m_WorldConfig->propertyModRequestsAllowedInterval = worldConfig.getIntField("propertyModRequestsAllowedInterval");
	m_WorldConfig->propertyModRequestsAllowedTotal = worldConfig.getIntField("propertyModRequestsAllowedTotal");
	m_WorldConfig->propertyModRequestsSpikeDuration = worldConfig.getIntField("propertyModRequestsSpikeDuration");
	m_WorldConfig->propertyModRequestsIntervalDuration = worldConfig.getIntField("propertyModRequestsIntervalDuration");

	m_WorldConfig->modelModerateOnCreate = worldConfig.getIntField("modelModerateOnCreate") != 0;

	m_WorldConfig->fReputationPerVote = worldConfig.getFloatField("fReputationPerVote");
	m_WorldConfig->reputationPerVoteCast = worldConfig.getFloatField("reputationPerVoteCast");
	m_WorldConfig->reputationPerVoteReceived = worldConfig.getFloatField("reputationPerVoteReceived");
	m_WorldConfig->reputationPerBattlePromotion = worldConfig.getFloatField("reputationPerBattlePromotion");

	m_WorldConfig->showcaseTopModelConsiderationBattles = worldConfig.getIntField("showcaseTopModelConsiderationBattles");

	m_WorldConfig->mailBaseFee = worldConfig.getIntField("mail_base_fee");
	m_WorldConfig->mailPercentAttachmentFee = worldConfig.getFloatField("mail_percent_attachment_fee");

	m_WorldConfig->levelCap = worldConfig.getIntField("LevelCap");
	m_WorldConfig->levelUpBehaviorEffect = worldConfig.getStringField("LevelUpBehaviorEffect");
	m_WorldConfig->levelCapCurrencyConversion = worldConfig.getIntField("LevelCapCurrencyConversion");

	LOG_DEBUG("Loaded WorldConfig into memory");
}
