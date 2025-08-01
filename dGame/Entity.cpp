#include "dCommonVars.h"
#include "Entity.h"
#include "CDClientManager.h"
#include "Game.h"
#include "Logger.h"
#include <functional>
#include "CDDestructibleComponentTable.h"
#include "CDClientDatabase.h"
#include <sstream>
#include "dServer.h"
#include "GameMessages.h"
#include "EntityManager.h"
#include "dZoneManager.h"
#include "Zone.h"
#include "Spawner.h"
#include "UserManager.h"
#include "dpWorld.h"
#include "LUTriggers.h"
#include "User.h"
#include "EntityTimer.h"
#include "EntityCallbackTimer.h"
#include "Loot.h"
#include "eMissionTaskType.h"
#include "eTriggerEventType.h"
#include "eObjectBits.h"
#include "PositionUpdate.h"
#include "MessageType/Chat.h"
#include "PlayerManager.h"

//Component includes:
#include "Component.h"
#include "ControllablePhysicsComponent.h"
#include "RenderComponent.h"
#include "MultiZoneEntranceComponent.h"
#include "CharacterComponent.h"
#include "DestroyableComponent.h"
#include "BuffComponent.h"
#include "BouncerComponent.h"
#include "InventoryComponent.h"
#include "LevelProgressionComponent.h"
#include "PlayerForcedMovementComponent.h"
#include "ScriptComponent.h"
#include "SkillComponent.h"
#include "SimplePhysicsComponent.h"
#include "SwitchComponent.h"
#include "PhantomPhysicsComponent.h"
#include "RigidbodyPhantomPhysicsComponent.h"
#include "MovingPlatformComponent.h"
#include "MissionComponent.h"
#include "MissionOfferComponent.h"
#include "QuickBuildComponent.h"
#include "BuildBorderComponent.h"
#include "MovementAIComponent.h"
#include "VendorComponent.h"
#include "DonationVendorComponent.h"
#include "RocketLaunchpadControlComponent.h"
#include "PropertyComponent.h"
#include "BaseCombatAIComponent.h"
#include "PropertyManagementComponent.h"
#include "PropertyVendorComponent.h"
#include "ProximityMonitorComponent.h"
#include "PropertyEntranceComponent.h"
#include "ModelComponent.h"
#include "ZCompression.h"
#include "PetComponent.h"
#include "HavokVehiclePhysicsComponent.h"
#include "PossessableComponent.h"
#include "PossessorComponent.h"
#include "ModuleAssemblyComponent.h"
#include "RacingControlComponent.h"
#include "SoundTriggerComponent.h"
#include "ShootingGalleryComponent.h"
#include "RailActivatorComponent.h"
#include "LUPExhibitComponent.h"
#include "RacingSoundTriggerComponent.h"
#include "TriggerComponent.h"
#include "eGameMasterLevel.h"
#include "eReplicaComponentType.h"
#include "eReplicaPacketType.h"
#include "MiniGameControlComponent.h"
#include "RacingStatsComponent.h"
#include "CollectibleComponent.h"
#include "ItemComponent.h"
#include "GhostComponent.h"
#include "AchievementVendorComponent.h"
#include "VanityUtilities.h"

// Table includes
#include "CDComponentsRegistryTable.h"
#include "CDCurrencyTableTable.h"
#include "CDMovementAIComponentTable.h"
#include "CDProximityMonitorComponentTable.h"
#include "CDRebuildComponentTable.h"
#include "CDObjectSkillsTable.h"
#include "CDObjectsTable.h"
#include "CDScriptComponentTable.h"
#include "CDSkillBehaviorTable.h"
#include "CDZoneTableTable.h"

#include "StringifiedEnum.h"

#include <ranges>

Observable<Entity*, const PositionUpdate&> Entity::OnPlayerPositionUpdate;

Entity::Entity(const LWOOBJID& objectID, const EntityInfo& info, User* parentUser, Entity* parentEntity) {
	m_ObjectID = objectID;
	m_TemplateID = info.lot;
	m_ParentEntity = parentEntity;
	m_Character = nullptr;
	m_GMLevel = eGameMasterLevel::CIVILIAN;
	m_NetworkID = 0;
	m_Groups = {};
	m_OwnerOverride = LWOOBJID_EMPTY;
	m_Timers = {};
	m_ChildEntities = {};
	m_ScheduleKiller = nullptr;
	m_TargetsInPhantom = {};
	m_Components = {};
	m_DieCallbacks = {};
	m_PhantomCollisionCallbacks = {};
	m_IsParentChildDirty = true;

	m_Settings = info.settings;
	m_NetworkSettings = info.networkSettings;
	m_DefaultPosition = info.pos;
	m_DefaultRotation = info.rot;
	m_Scale = info.scale;
	m_Spawner = info.spawner;
	m_SpawnerID = info.spawnerID;
	m_HasSpawnerNodeID = info.hasSpawnerNodeID;
	m_SpawnerNodeID = info.spawnerNodeID;

	m_PlayerIsReadyForUpdates = info.lot != 1;

	if (parentUser) {
		m_Character = parentUser->GetLastUsedChar();
		parentUser->SetLoggedInChar(objectID);
		m_GMLevel = m_Character->GetGMLevel();

		m_Character->SetEntity(this);

		PlayerManager::AddPlayer(this);
	}
}

Entity::~Entity() {
	if (IsPlayer()) {
		LOG("Deleted player");

		// Make sure the player exists first.  Remove afterwards to prevent the OnPlayerExist functions from not being able to find the player.
		if (!PlayerManager::RemovePlayer(this)) {
			LOG("Unable to find player to remove from manager.");
			return;
		}

		auto* zoneControl = Game::entityManager->GetZoneControlEntity();
		if (zoneControl) {
			zoneControl->GetScript()->OnPlayerExit(zoneControl, this);
		}

		std::vector<Entity*> scriptedActs = Game::entityManager->GetEntitiesByComponent(eReplicaComponentType::SCRIPTED_ACTIVITY);
		for (Entity* scriptEntity : scriptedActs) {
			if (zoneControl && scriptEntity->GetObjectID() != zoneControl->GetObjectID()) { // Don't want to trigger twice on instance worlds
				scriptEntity->GetScript()->OnPlayerExit(scriptEntity, this);
			}
		}
	}

	if (m_Character) {
		m_Character->SaveXMLToDatabase();
		m_Character->SetEntity(nullptr);
	}

	CancelAllTimers();
	CancelCallbackTimers();

	for (const auto& component : m_Components | std::views::values) {
		if (component) delete component;
	}

	for (auto* const child : m_ChildEntities) {
		if (child) child->RemoveParent();
	}

	if (m_ParentEntity) {
		m_ParentEntity->RemoveChild(this);
	}
}

void Entity::Initialize() {
	RegisterMsg(MessageType::Game::REQUEST_SERVER_OBJECT_INFO, this, &Entity::MsgRequestServerObjectInfo);
	/**
	 * Setup trigger
	 */

	const auto triggerInfo = GetVarAsString(u"trigger_id");

	if (!triggerInfo.empty()) AddComponent<TriggerComponent>(triggerInfo);

	/**
	 * Setup groups
	 */

	const auto groupIDs = GetVarAsString(u"groupID");

	if (!groupIDs.empty()) {
		m_Groups = GeneralUtils::SplitString(groupIDs, ';');
		if (!m_Groups.empty()) {
			if (m_Groups.back().empty()) m_Groups.erase(m_Groups.end() - 1);
		}
	}

	/**
	 * Set ourselves as a child of our parent
	 */

	if (m_ParentEntity != nullptr) {
		m_ParentEntity->AddChild(this);
	}

	// Get the registry table
	CDComponentsRegistryTable* const compRegistryTable = CDClientManager::GetTable<CDComponentsRegistryTable>();

	/**
	 * Special case for BBB models. They have components not corresponding to the registry.
	 */

	if (m_TemplateID == 14) {
		const auto simplePhysicsComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SIMPLE_PHYSICS);

		AddComponent<SimplePhysicsComponent>(simplePhysicsComponentID);

		AddComponent<ModelComponent>()->LoadBehaviors();

		AddComponent<RenderComponent>();

		auto* destroyableComponent = AddComponent<DestroyableComponent>();
		destroyableComponent->SetHealth(1);
		destroyableComponent->SetMaxHealth(1.0f);
		destroyableComponent->SetFaction(-1, true);
		destroyableComponent->SetIsSmashable(true);
		// We have all our components.
		return;
	}

	/**
	 * Go through all the components and check if this entity has them.
	 *
	 * Not all components are implemented. Some are represented by a nullptr, as they hold no data.
	 */

	if (m_Character && m_Character->GetParentUser()) {
		AddComponent<MissionComponent>()->LoadFromXml(m_Character->GetXMLDoc());
	}

	const uint32_t petComponentId = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::PET);
	if (petComponentId > 0) {
		AddComponent<PetComponent>(petComponentId);
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::MINI_GAME_CONTROL) > 0) {
		AddComponent<MiniGameControlComponent>();
	}

	const uint32_t possessableComponentId = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::POSSESSABLE);
	if (possessableComponentId > 0) {
		AddComponent<PossessableComponent>(possessableComponentId);
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::MODULE_ASSEMBLY) > 0) {
		AddComponent<ModuleAssemblyComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::RACING_STATS) > 0) {
		AddComponent<RacingStatsComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::LUP_EXHIBIT, -1) >= 0) {
		AddComponent<LUPExhibitComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::RACING_CONTROL) > 0) {
		AddComponent<RacingControlComponent>();
	}

	const auto propertyEntranceComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::PROPERTY_ENTRANCE);
	if (propertyEntranceComponentID > 0) {
		AddComponent<PropertyEntranceComponent>(propertyEntranceComponentID);
	}

	const int32_t controllablePhysicsComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::CONTROLLABLE_PHYSICS);
	if (controllablePhysicsComponentID > 0) {
		auto* controllablePhysics = AddComponent<ControllablePhysicsComponent>(controllablePhysicsComponentID);

		if (m_Character) {
			controllablePhysics->LoadFromXml(m_Character->GetXMLDoc());

			const auto mapID = Game::server->GetZoneID();

			//If we came from another zone, put us in the starting loc
			if (m_Character->GetZoneID() != Game::server->GetZoneID() || mapID == 1603) { // Exception for Moon Base as you tend to spawn on the roof.
				NiPoint3 pos;
				NiQuaternion rot;

				const auto& targetSceneName = m_Character->GetTargetScene();
				auto* targetScene = Game::entityManager->GetSpawnPointEntity(targetSceneName);

				if (m_Character->HasBeenToWorld(mapID) && targetSceneName.empty()) {
					pos = m_Character->GetRespawnPoint(mapID);
					rot = Game::zoneManager->GetZone()->GetSpawnRot();
				} else if (targetScene != nullptr) {
					pos = targetScene->GetPosition();
					rot = targetScene->GetRotation();
				} else {
					pos = Game::zoneManager->GetZone()->GetSpawnPos();
					rot = Game::zoneManager->GetZone()->GetSpawnRot();
				}

				controllablePhysics->SetPosition(pos);
				controllablePhysics->SetRotation(rot);
			}
		} else {
			controllablePhysics->SetPosition(m_DefaultPosition);
			controllablePhysics->SetRotation(m_DefaultRotation);
		}
	}

	// If an entity is marked a phantom, simple physics is made into phantom phyics.
	const bool markedAsPhantom = GetVar<bool>(u"markedAsPhantom");

	const auto simplePhysicsComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SIMPLE_PHYSICS);
	if (!markedAsPhantom && simplePhysicsComponentID > 0) {
		AddComponent<SimplePhysicsComponent>(simplePhysicsComponentID);
	}

	const int32_t rigidBodyPhantomPhysicsComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::RIGID_BODY_PHANTOM_PHYSICS);
	if (rigidBodyPhantomPhysicsComponentID > 0) {
		AddComponent<RigidbodyPhantomPhysicsComponent>(rigidBodyPhantomPhysicsComponentID);
	}

	const int32_t phantomPhysicsComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::PHANTOM_PHYSICS);
	if (markedAsPhantom || phantomPhysicsComponentID > 0) {
		AddComponent<PhantomPhysicsComponent>(phantomPhysicsComponentID)->SetPhysicsEffectActive(false);
	}

	const int32_t havokVehiclePhysicsComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::HAVOK_VEHICLE_PHYSICS);
	if (havokVehiclePhysicsComponentID > 0) {
		auto* havokVehiclePhysicsComponent = AddComponent<HavokVehiclePhysicsComponent>(havokVehiclePhysicsComponentID);
		havokVehiclePhysicsComponent->SetPosition(m_DefaultPosition);
		havokVehiclePhysicsComponent->SetRotation(m_DefaultRotation);
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SOUND_TRIGGER, -1) != -1) {
		AddComponent<SoundTriggerComponent>();
	} else if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::RACING_SOUND_TRIGGER, -1) != -1) {
		AddComponent<RacingSoundTriggerComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::BUFF) > 0) {
		AddComponent<BuffComponent>();
	}

	const int collectibleComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::COLLECTIBLE);

	if (collectibleComponentID > 0) {
		AddComponent<CollectibleComponent>(GetVarAs<int32_t>(u"collectible_id"));
	}

	/**
	 * Multiple components require the destructible component.
	 */
	const int buffComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::BUFF);
	const int quickBuildComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::QUICK_BUILD);

	int componentID = -1;
	if (collectibleComponentID > 0) componentID = collectibleComponentID;
	if (quickBuildComponentID > 0) componentID = quickBuildComponentID;
	if (buffComponentID > 0) componentID = buffComponentID;


	bool isSmashable = GetVarAs<int32_t>(u"is_smashable") != 0;
	if (buffComponentID > 0 || collectibleComponentID > 0 || isSmashable) {
		DestroyableComponent* comp = AddComponent<DestroyableComponent>();
		auto* const destCompTable = CDClientManager::GetTable<CDDestructibleComponentTable>();
		std::vector<CDDestructibleComponent> destCompData = destCompTable->Query([componentID](const CDDestructibleComponent& entry) { return (entry.id == componentID); });

		if (m_Character) {
			comp->LoadFromXml(m_Character->GetXMLDoc());
		} else {
			// extraInfo overrides. Client ORs the database smashable and the luz smashable.
			comp->SetIsSmashable(comp->GetIsSmashable() || isSmashable);

			if (componentID > 0) {
				if (!destCompData.empty()) {
					if (HasComponent(eReplicaComponentType::RACING_STATS)) {
						destCompData[0].imagination = 60;
					}

					comp->SetHealth(destCompData[0].life);
					comp->SetImagination(destCompData[0].imagination);
					comp->SetArmor(destCompData[0].armor);

					comp->SetMaxHealth(destCompData[0].life);
					comp->SetMaxImagination(destCompData[0].imagination);
					comp->SetMaxArmor(destCompData[0].armor);
					comp->SetDeathBehavior(destCompData[0].death_behavior);

					comp->SetIsSmashable(destCompData[0].isSmashable);

					comp->SetLootMatrixID(destCompData[0].LootMatrixIndex);
					Loot::CacheMatrix(destCompData[0].LootMatrixIndex);

					// Now get currency information
					const uint32_t npcMinLevel = destCompData[0].level;
					const uint32_t currencyIndex = destCompData[0].CurrencyIndex;

					CDCurrencyTableTable* const currencyTable = CDClientManager::GetTable<CDCurrencyTableTable>();
					const std::vector<CDCurrencyTable> currencyValues = currencyTable->Query([currencyIndex, npcMinLevel](const CDCurrencyTable& entry) { return (entry.currencyIndex == currencyIndex && entry.npcminlevel == npcMinLevel); });

					if (!currencyValues.empty()) {
						// Set the coins
						comp->SetMinCoins(currencyValues[0].minvalue);
						comp->SetMaxCoins(currencyValues[0].maxvalue);
					}
				}
			} else {
				comp->SetHealth(1);
				comp->SetArmor(0);

				comp->SetMaxHealth(1);
				comp->SetMaxArmor(0);

				comp->SetIsSmashable(true);
				comp->AddFaction(-1);
				comp->AddFaction(6); //Smashables

				// A race car has 60 imagination, other entities defaults to 0.
				comp->SetImagination(HasComponent(eReplicaComponentType::RACING_STATS) ? 60 : 0);
				comp->SetMaxImagination(HasComponent(eReplicaComponentType::RACING_STATS) ? 60 : 0);
			}
		}

		if (!destCompData.empty()) {
			comp->AddFaction(destCompData[0].faction);
			std::stringstream ss(destCompData[0].factionList);
			std::string token;

			while (std::getline(ss, token, ',')) {
				const auto tokenInt = GeneralUtils::TryParse<int32_t>(token);
				if (tokenInt == destCompData[0].faction) continue;

				if (!token.empty()) {
					comp->AddFaction(std::stoi(token));
				}
			}
		}

		// override the factions if needed.
		const auto setFaction = GetVarAsString(u"set_faction");
		if (!setFaction.empty()) {
			// TODO also split on space here however we do not have a general util for splitting on multiple characters yet.
			const auto factionsToAdd = GeneralUtils::SplitString(setFaction, ';');
			for (const auto& faction : factionsToAdd) {
				const auto factionToAdd = GeneralUtils::TryParse<int32_t>(faction);
				if (factionToAdd) {
					comp->AddFaction(factionToAdd.value(), true);
				}
			}
		}
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::CHARACTER) > 0 || m_Character) {
		// Character Component always has a possessor, level, and forced movement components
		AddComponent<PossessorComponent>();

		// load in the xml for the level
		AddComponent<LevelProgressionComponent>()->LoadFromXml(m_Character->GetXMLDoc());

		AddComponent<PlayerForcedMovementComponent>();

		auto& systemAddress = m_Character->GetParentUser() ? m_Character->GetParentUser()->GetSystemAddress() : UNASSIGNED_SYSTEM_ADDRESS;
		AddComponent<CharacterComponent>(m_Character, systemAddress)->LoadFromXml(m_Character->GetXMLDoc());

		AddComponent<GhostComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::INVENTORY) > 0 || m_Character) {
		AddComponent<InventoryComponent>();
	}
	// if this component exists, then we initialize it. it's value is always 0
	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::MULTI_ZONE_ENTRANCE, -1) != -1) {
		AddComponent<MultiZoneEntranceComponent>();
	}

	/**
	 * This is a bit of a mess
	 * yep i aint touching this
	 */

	CDScriptComponentTable* const scriptCompTable = CDClientManager::GetTable<CDScriptComponentTable>();
	const int32_t scriptComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SCRIPT, -1);

	std::string scriptName = "";
	bool client = false;
	if (scriptComponentID > 0 || m_Character) {
		std::string clientScriptName;
		if (!m_Character) {
			CDScriptComponent scriptCompData = scriptCompTable->GetByID(scriptComponentID);
			scriptName = scriptCompData.script_name;
			clientScriptName = scriptCompData.client_script_name;
		} else {
			scriptName = "";
		}

		if (scriptName != "" || (scriptName == "" && m_Character)) {

		} else if (clientScriptName != "") {
			client = true;
		} else if (!m_Character) {
			client = true;
		}
	}

	std::string customScriptServer;
	bool hasCustomServerScript = false;

	const auto customScriptServerName = GetVarAsString(u"custom_script_server");
	const auto customScriptClientName = GetVarAsString(u"custom_script_client");

	if (!customScriptServerName.empty()) {
		customScriptServer = customScriptServerName;
		hasCustomServerScript = true;
	}

	if (!customScriptClientName.empty()) {
		client = true;
	}

	if (hasCustomServerScript && scriptName.empty()) {
		scriptName = customScriptServer;
	}

	if (!scriptName.empty() || client || m_Character || scriptComponentID >= 0) {
		AddComponent<ScriptComponent>(scriptName, true, client && scriptName.empty());
	}

	// ZoneControl script
	if (m_TemplateID == 2365) {
		const auto& zoneID = Game::zoneManager->GetZoneID();
		const CDZoneTable* const zoneData = CDZoneTableTable::Query(zoneID.GetMapID());

		if (zoneData != nullptr) {
			int zoneScriptID = zoneData->scriptID;
			CDScriptComponent zoneScriptData = scriptCompTable->GetByID(zoneScriptID);
			AddComponent<ScriptComponent>(zoneScriptData.script_name, true);
		}
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SKILL, -1) != -1 || m_Character) {
		AddComponent<SkillComponent>();
	}

	const auto combatAiId = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::BASE_COMBAT_AI);
	if (combatAiId > 0) {
		AddComponent<BaseCombatAIComponent>(combatAiId);
	}

	if (const int componentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::QUICK_BUILD) > 0) {
		auto* const quickBuildComponent = AddComponent<QuickBuildComponent>();

		CDRebuildComponentTable* const rebCompTable = CDClientManager::GetTable<CDRebuildComponentTable>();
		const std::vector<CDRebuildComponent> rebCompData = rebCompTable->Query([=](CDRebuildComponent entry) { return (entry.id == quickBuildComponentID); });

		if (!rebCompData.empty()) {
			quickBuildComponent->SetResetTime(rebCompData[0].reset_time);
			quickBuildComponent->SetCompleteTime(rebCompData[0].complete_time);
			quickBuildComponent->SetTakeImagination(rebCompData[0].take_imagination);
			quickBuildComponent->SetInterruptible(rebCompData[0].interruptible);
			quickBuildComponent->SetSelfActivator(rebCompData[0].self_activator);
			quickBuildComponent->SetActivityId(rebCompData[0].activityID);
			quickBuildComponent->SetPostImaginationCost(rebCompData[0].post_imagination_cost);
			quickBuildComponent->SetTimeBeforeSmash(rebCompData[0].time_before_smash);

			const auto rebuildResetTime = GetVar<float>(u"rebuild_reset_time");

			if (rebuildResetTime != 0.0f) {
				quickBuildComponent->SetResetTime(rebuildResetTime);

				// Known bug with moving platform in FV that casues it to build at the end instead of the start.
				// This extends the smash time so players can ride up the lift.
				if (m_TemplateID == 9483) {
					quickBuildComponent->SetResetTime(quickBuildComponent->GetResetTime() + 25);
				}
			}

			const auto activityID = GetVar<int32_t>(u"activityID");

			if (activityID > 0) {
				quickBuildComponent->SetActivityId(activityID);
				Loot::CacheMatrix(activityID);
			}

			const auto timeBeforeSmash = GetVar<float>(u"tmeSmsh");

			if (timeBeforeSmash > 0) {
				quickBuildComponent->SetTimeBeforeSmash(timeBeforeSmash);
			}

			const auto compTime = GetVar<float>(u"compTime");

			if (compTime > 0) {
				quickBuildComponent->SetCompleteTime(compTime);
			}
		}
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SWITCH, -1) != -1) {
		AddComponent<SwitchComponent>();
	}

	if ((compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::VENDOR) > 0)) {
		AddComponent<VendorComponent>();
	} else if ((compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::DONATION_VENDOR, -1) != -1)) {
		AddComponent<DonationVendorComponent>();
	} else if ((compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::ACHIEVEMENT_VENDOR, -1) != -1)) {
		AddComponent<AchievementVendorComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::PROPERTY_VENDOR, -1) != -1) {
		AddComponent<PropertyVendorComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::PROPERTY_MANAGEMENT, -1) != -1) {
		AddComponent<PropertyManagementComponent>();
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::BOUNCER, -1) != -1) { // you have to determine it like this because all bouncers have a componentID of 0
		AddComponent<BouncerComponent>();
	}

	const int32_t renderComponentId = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::RENDER);
	if ((renderComponentId > 0 && m_TemplateID != 2365) || m_Character) {
		AddComponent<RenderComponent>(renderComponentId);
	}

	if ((compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::MISSION_OFFER) > 0) || m_Character) {
		AddComponent<MissionOfferComponent>(m_TemplateID);
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::BUILD_BORDER, -1) != -1) {
		AddComponent<BuildBorderComponent>();
	}

	// Scripted activity component
	const int32_t scriptedActivityID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SCRIPTED_ACTIVITY, -1);
	if (scriptedActivityID != -1) {
		AddComponent<ScriptedActivityComponent>(scriptedActivityID);
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::MODEL, -1) != -1 && !GetComponent<PetComponent>()) {
		AddComponent<ModelComponent>()->LoadBehaviors();
		if (!HasComponent(eReplicaComponentType::DESTROYABLE)) {
			auto* const destroyableComponent = AddComponent<DestroyableComponent>();
			destroyableComponent->SetHealth(1);
			destroyableComponent->SetMaxHealth(1.0f);
			destroyableComponent->SetFaction(-1, true);
			destroyableComponent->SetIsSmashable(true);
		}
	}

	PetComponent* petComponent;
	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::ITEM) > 0 && !TryGetComponent(eReplicaComponentType::PET, petComponent) && !HasComponent(eReplicaComponentType::MODEL)) {
		AddComponent<ItemComponent>();
	}

	// Shooting gallery component
	const auto shootingGalleryComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::SHOOTING_GALLERY);
	if (shootingGalleryComponentID > 0) {
		AddComponent<ShootingGalleryComponent>(shootingGalleryComponentID);
	}

	if (compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::PROPERTY, -1) != -1) {
		AddComponent<PropertyComponent>();
	}

	const int rocketId = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::ROCKET_LAUNCH);
	if ((rocketId > 0)) {
		AddComponent<RocketLaunchpadControlComponent>(rocketId);
	}

	const int32_t railComponentID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::RAIL_ACTIVATOR);
	if (railComponentID > 0) {
		AddComponent<RailActivatorComponent>(railComponentID);
	}

	const int movementAIID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::MOVEMENT_AI);
	if (movementAIID > 0) {
		CDMovementAIComponentTable* moveAITable = CDClientManager::GetTable<CDMovementAIComponentTable>();
		std::vector<CDMovementAIComponent> moveAIComp = moveAITable->Query([=](CDMovementAIComponent entry) {return (entry.id == movementAIID); });

		if (moveAIComp.size() > 0) {
			MovementAIInfo moveInfo{
				.movementType = moveAIComp[0].MovementType,
				.wanderRadius = moveAIComp[0].WanderRadius,
				.wanderSpeed = moveAIComp[0].WanderSpeed,
				.wanderChance = moveAIComp[0].WanderChance,
				.wanderDelayMin = moveAIComp[0].WanderDelayMin,
				.wanderDelayMax = moveAIComp[0].WanderDelayMax,
			};

			const bool useWanderDB = GetVar<bool>(u"usewanderdb");

			if (!useWanderDB) {
				const auto wanderOverride = GetVarAs<float>(u"wanderRadius");

				if (wanderOverride != 0.0f) {
					moveInfo.wanderRadius = wanderOverride;
				}
			}

			AddComponent<MovementAIComponent>(moveInfo);
		}
	} else if (petComponentId > 0 || combatAiId > 0 && GetComponent<BaseCombatAIComponent>()->GetTetherSpeed() > 0) {
		MovementAIInfo moveInfo{
			.movementType = "",
			.wanderRadius = 16,
			.wanderSpeed = 2.5f,
			.wanderChance = 0,
			.wanderDelayMin = 2,
			.wanderDelayMax = 5,
		};

		AddComponent<MovementAIComponent>(moveInfo);
	}

	const std::string pathName = GetVarAsString(u"attached_path");
	const Path* const path = Game::zoneManager->GetZone()->GetPath(pathName);

	//Check to see if we have an attached path and add the appropiate component to handle it:
	if (path) {
		// if we have a moving platform path, then we need a moving platform component
		if (path->pathType == PathType::MovingPlatform) {
			AddComponent<MovingPlatformComponent>(pathName);
		} else if (path->pathType == PathType::Movement) {
			auto* const movementAIcomponent = GetComponent<MovementAIComponent>();
			if (movementAIcomponent && combatAiId == 0) {
				movementAIcomponent->SetPath(pathName);
			} else {
				MovementAIInfo moveInfo{
					.movementType = "",
					.wanderRadius = 16,
					.wanderSpeed = 2.5f,
					.wanderChance = 0,
					.wanderDelayMin = 2,
					.wanderDelayMax = 5,
				};

				AddComponent<MovementAIComponent>(moveInfo);
			}
		}
	} else {
		// else we still need to setup moving platform if it has a moving platform comp but no path
		const int32_t movingPlatformComponentId = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::MOVING_PLATFORM, -1);
		if (movingPlatformComponentId >= 0) {
			AddComponent<MovingPlatformComponent>(pathName);
		}
	}

	const int proximityMonitorID = compRegistryTable->GetByIDAndType(m_TemplateID, eReplicaComponentType::PROXIMITY_MONITOR);
	if (proximityMonitorID > 0) {
		auto* const proxCompTable = CDClientManager::GetTable<CDProximityMonitorComponentTable>();
		const auto proxCompData = proxCompTable->Query([proximityMonitorID](const CDProximityMonitorComponent& entry) { return (entry.id == proximityMonitorID); });
		if (proxCompData.size() > 0) {
			std::vector<std::string> proximityStr = GeneralUtils::SplitString(proxCompData[0].Proximities, ',');
			AddComponent<ProximityMonitorComponent>(std::stoi(proximityStr[0]), std::stoi(proximityStr[1]));
		}
	}

	// Hacky way to trigger these when the object has had a chance to get constructed
	AddCallbackTimer(0, [this]() {
		this->GetScript()->OnStartup(this);
		if (this->m_ParentEntity) {
			GameMessages::ChildLoaded childLoaded;
			childLoaded.childID = this->m_ObjectID;
			childLoaded.templateID = this->GetLOT();
			this->m_ParentEntity->OnChildLoaded(childLoaded);
		}
		});

	if (!m_Character && Game::entityManager->GetGhostingEnabled()) {
		// Don't ghost what is likely large scene elements
		if (HasComponent(eReplicaComponentType::SIMPLE_PHYSICS) && HasComponent(eReplicaComponentType::RENDER) && (m_Components.size() == 2 || (HasComponent(eReplicaComponentType::TRIGGER) && m_Components.size() == 3))) {
			goto no_ghosting;
		}

		/* Filter for ghosting candidates.
		 *
		 * Don't ghost moving platforms, until we've got proper syncing for those.
		 * Don't ghost big phantom physics triggers, as putting those to sleep might prevent interactions.
		 * Don't ghost property related objects, as the client expects those to always be loaded.
		 */
		if (
			!EntityManager::IsExcludedFromGhosting(GetLOT()) &&
			!HasComponent(eReplicaComponentType::SCRIPTED_ACTIVITY) &&
			!HasComponent(eReplicaComponentType::MOVING_PLATFORM) &&
			!HasComponent(eReplicaComponentType::PHANTOM_PHYSICS) &&
			!HasComponent(eReplicaComponentType::PROPERTY) &&
			!HasComponent(eReplicaComponentType::RACING_CONTROL) &&
			!HasComponent(eReplicaComponentType::HAVOK_VEHICLE_PHYSICS)
			)
			//if (HasComponent(eReplicaComponentType::BASE_COMBAT_AI))
		{
			m_IsGhostingCandidate = true;
		}

		if (GetLOT() == 6368) {
			m_IsGhostingCandidate = true;
		}

		// Special case for collectibles in Ninjago
		if (HasComponent(eReplicaComponentType::COLLECTIBLE) && Game::server->GetZoneID() == 2000) {
			m_IsGhostingCandidate = true;
		}
	}

no_ghosting:

	TriggerEvent(eTriggerEventType::CREATE, this);

	if (m_Character) {
		auto* controllablePhysicsComponent = GetComponent<ControllablePhysicsComponent>();
		auto* levelComponent = GetComponent<LevelProgressionComponent>();

		if (controllablePhysicsComponent && levelComponent) {
			controllablePhysicsComponent->SetSpeedMultiplier(levelComponent->GetSpeedBase() / 500.0f);
		}
	}
}

bool Entity::operator==(const Entity& other) const {
	return other.m_ObjectID == m_ObjectID;
}

bool Entity::operator!=(const Entity& other) const {
	return !operator==(other);
}

Component* Entity::GetComponent(eReplicaComponentType componentID) const {
	const auto& index = m_Components.find(componentID);
	return index != m_Components.end() ? index->second : nullptr;
}

bool Entity::HasComponent(const eReplicaComponentType componentId) const {
	return m_Components.contains(componentId);
}

void Entity::Subscribe(LWOOBJID scriptObjId, CppScripts::Script* scriptToAdd, const std::string& notificationName) {
	if (notificationName == "HitOrHealResult" || notificationName == "Hit") {
		auto* const  destroyableComponent = GetComponent<DestroyableComponent>();
		if (!destroyableComponent) return;
		destroyableComponent->Subscribe(scriptObjId, scriptToAdd);
	} else if (notificationName == "PlayerResurrectionFinished") {
		LOG("Subscribing to PlayerResurrectionFinished");
		m_Subscriptions[scriptObjId][notificationName] = scriptToAdd;
	}
}

void Entity::Unsubscribe(LWOOBJID scriptObjId, const std::string& notificationName) {
	if (notificationName == "HitOrHealResult" || notificationName == "Hit") {
		auto* const  destroyableComponent = GetComponent<DestroyableComponent>();
		if (!destroyableComponent) return;
		destroyableComponent->Unsubscribe(scriptObjId);
	} else if (notificationName == "PlayerResurrectionFinished") {
		LOG("Unsubscribing from PlayerResurrectionFinished");
		m_Subscriptions[scriptObjId].erase(notificationName);
	}
}

void Entity::SetProximityRadius(float proxRadius, std::string name) {
	auto* proxMon = GetComponent<ProximityMonitorComponent>();
	if (!proxMon) proxMon = AddComponent<ProximityMonitorComponent>();
	proxMon->SetProximityRadius(proxRadius, name);
}

void Entity::SetProximityRadius(dpEntity* entity, std::string name) {
	ProximityMonitorComponent* proxMon = AddComponent<ProximityMonitorComponent>();
	proxMon->SetProximityRadius(entity, name);
}

void Entity::SetGMLevel(eGameMasterLevel value) {
	m_GMLevel = value;
	if (m_Character) m_Character->SetGMLevel(value);

	auto* const characterComponent = GetComponent<CharacterComponent>();
	if (!characterComponent) return;

	characterComponent->SetGMLevel(value);

	GameMessages::SendGMLevelBroadcast(m_ObjectID, value);

	// Update the chat server of our GM Level
	{
		CBITSTREAM;
		BitStreamUtils::WriteHeader(bitStream, eConnectionType::CHAT, MessageType::Chat::GMLEVEL_UPDATE);
		bitStream.Write(m_ObjectID);
		bitStream.Write(m_GMLevel);

		Game::chatServer->Send(&bitStream, SYSTEM_PRIORITY, RELIABLE, 0, Game::chatSysAddr, false);
	}
}

void Entity::WriteLDFData(const std::vector<LDFBaseData*>& ldf, RakNet::BitStream& outBitStream) const {
	RakNet::BitStream settingStream;
	int32_t numberOfValidKeys = ldf.size();

	// Writing keys value pairs the client does not expect to receive or interpret will result in undefined behavior,
	// so we need to filter out any keys that are not valid and fix the number of valid keys to be correct.
	for (LDFBaseData* data : ldf) {
		if (data && data->GetValueType() != eLDFType::LDF_TYPE_UNKNOWN) {
			data->WriteToPacket(settingStream);
		} else {
			numberOfValidKeys--;
		}
	}

	// Now write it to the main bitstream
	outBitStream.Write<uint32_t>(settingStream.GetNumberOfBytesUsed() + 1 + sizeof(uint32_t));
	outBitStream.Write<uint8_t>(0); //no compression used
	outBitStream.Write(numberOfValidKeys);
	outBitStream.Write(settingStream);
}

void Entity::WriteBaseReplicaData(RakNet::BitStream& outBitStream, eReplicaPacketType packetType) {
	if (packetType == eReplicaPacketType::CONSTRUCTION) {
		outBitStream.Write(m_ObjectID);
		outBitStream.Write(m_TemplateID);

		const auto& name = GeneralUtils::ASCIIToUTF16(IsPlayer() ?
			m_Character ? m_Character->GetName() : "Invalid"
			: GetVar<std::string>(u"npcName"));

		outBitStream.Write<uint8_t>(name.size());
		outBitStream.Write(name);

		outBitStream.Write<uint32_t>(0); //Time since created on server

		const auto& syncLDF = GetVar<std::vector<std::u16string>>(u"syncLDF");

		// Only sync for models.
		if (!m_Settings.empty() && (GetComponent<ModelComponent>() && !GetComponent<PetComponent>())) {
			outBitStream.Write1(); // Has ldf data
			WriteLDFData(m_Settings, outBitStream);
		} else if (!syncLDF.empty()) {
			// Find all the ldf data we need to write
			std::vector<LDFBaseData*> ldfData;
			ldfData.reserve(m_Settings.size());

			for (const auto& data : syncLDF) {
				ldfData.push_back(GetVarData(data));
			}

			outBitStream.Write1(); // Has ldf data
			WriteLDFData(ldfData, outBitStream);
		} else {
			outBitStream.Write0(); // No ldf data
		}

		const auto* const triggerComponent = GetComponent<TriggerComponent>();
		if (triggerComponent) {
			// Has trigger component, check to see if we have events to handle
			auto* trigger = triggerComponent->GetTrigger();
			outBitStream.Write<bool>(trigger && !trigger->events.empty());
		} else { // No trigger componenet, so definitely no triggers
			outBitStream.Write0();
		}

		const bool hasParent = m_ParentEntity != nullptr || m_SpawnerID != 0;
		outBitStream.Write(hasParent);
		if (hasParent) {
			if (m_ParentEntity != nullptr) outBitStream.Write(GeneralUtils::SetBit(m_ParentEntity->GetObjectID(), static_cast<uint32_t>(eObjectBits::CLIENT)));
			else if (m_Spawner != nullptr && m_Spawner->m_Info.isNetwork) outBitStream.Write(m_SpawnerID);
			else outBitStream.Write(GeneralUtils::SetBit(m_SpawnerID, static_cast<uint32_t>(eObjectBits::CLIENT)));
		}

		outBitStream.Write(m_HasSpawnerNodeID);
		if (m_HasSpawnerNodeID) outBitStream.Write(m_SpawnerNodeID);

		// This zero check should not be here?
		const bool hasDefaultScale = m_Scale != 1.0f && m_Scale != 0.0f;
		outBitStream.Write(hasDefaultScale);
		if (hasDefaultScale) outBitStream.Write(m_Scale);

		outBitStream.Write0(); //ObjectWorldState

		const bool hasGMLevel = m_GMLevel != eGameMasterLevel::CIVILIAN;
		outBitStream.Write(hasGMLevel);
		if (hasGMLevel) outBitStream.Write(m_GMLevel);
	}

	// Only serialize parent / child info should the info be dirty (changed) or if this is the construction of the entity.
	const bool writeParentChild = m_IsParentChildDirty || packetType == eReplicaPacketType::CONSTRUCTION;
	outBitStream.Write(writeParentChild);
	if (writeParentChild) {
		m_IsParentChildDirty = false;
		outBitStream.Write(m_ParentEntity != nullptr);
		if (m_ParentEntity) {
			outBitStream.Write(m_ParentEntity->GetObjectID());
			outBitStream.Write0(); // Updates position with parent, usually false in live. Haven't seen a case where its supposed to be true
		}
		outBitStream.Write(!m_ChildEntities.empty());
		if (!m_ChildEntities.empty()) {
			outBitStream.Write<uint16_t>(m_ChildEntities.size());
			for (const auto* const child : m_ChildEntities) {
				if (child) outBitStream.Write<LWOOBJID>(child->GetObjectID());
			}
		}
	}
}

void Entity::WriteComponents(RakNet::BitStream& outBitStream, eReplicaPacketType packetType) const {

	/**
	 * This has to be done in a specific order.
	 */

	bool destroyableSerialized = false;
	bool bIsInitialUpdate = packetType == eReplicaPacketType::CONSTRUCTION;

	PossessableComponent* possessableComponent;
	if (TryGetComponent(eReplicaComponentType::POSSESSABLE, possessableComponent)) {
		possessableComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	ModuleAssemblyComponent* moduleAssemblyComponent;
	if (TryGetComponent(eReplicaComponentType::MODULE_ASSEMBLY, moduleAssemblyComponent)) {
		moduleAssemblyComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	ControllablePhysicsComponent* controllablePhysicsComponent;
	if (TryGetComponent(eReplicaComponentType::CONTROLLABLE_PHYSICS, controllablePhysicsComponent)) {
		controllablePhysicsComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	SimplePhysicsComponent* simplePhysicsComponent;
	if (TryGetComponent(eReplicaComponentType::SIMPLE_PHYSICS, simplePhysicsComponent)) {
		simplePhysicsComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	RigidbodyPhantomPhysicsComponent* rigidbodyPhantomPhysics;
	if (TryGetComponent(eReplicaComponentType::RIGID_BODY_PHANTOM_PHYSICS, rigidbodyPhantomPhysics)) {
		rigidbodyPhantomPhysics->Serialize(outBitStream, bIsInitialUpdate);
	}

	HavokVehiclePhysicsComponent* havokVehiclePhysicsComponent;
	if (TryGetComponent(eReplicaComponentType::HAVOK_VEHICLE_PHYSICS, havokVehiclePhysicsComponent)) {
		havokVehiclePhysicsComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	PhantomPhysicsComponent* phantomPhysicsComponent;
	if (TryGetComponent(eReplicaComponentType::PHANTOM_PHYSICS, phantomPhysicsComponent)) {
		phantomPhysicsComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	SoundTriggerComponent* soundTriggerComponent;
	if (TryGetComponent(eReplicaComponentType::SOUND_TRIGGER, soundTriggerComponent)) {
		soundTriggerComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	RacingSoundTriggerComponent* racingSoundTriggerComponent;
	if (TryGetComponent(eReplicaComponentType::RACING_SOUND_TRIGGER, racingSoundTriggerComponent)) {
		racingSoundTriggerComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	BuffComponent* buffComponent;
	if (TryGetComponent(eReplicaComponentType::BUFF, buffComponent)) {
		buffComponent->Serialize(outBitStream, bIsInitialUpdate);

		DestroyableComponent* destroyableComponent;
		if (TryGetComponent(eReplicaComponentType::DESTROYABLE, destroyableComponent)) {
			destroyableComponent->Serialize(outBitStream, bIsInitialUpdate);
		}
		destroyableSerialized = true;
	}

	CollectibleComponent* collectibleComponent;
	if (TryGetComponent(eReplicaComponentType::COLLECTIBLE, collectibleComponent)) {
		DestroyableComponent* destroyableComponent;
		if (TryGetComponent(eReplicaComponentType::DESTROYABLE, destroyableComponent) && !destroyableSerialized) {
			destroyableComponent->Serialize(outBitStream, bIsInitialUpdate);
		}
		destroyableSerialized = true;
		collectibleComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	PetComponent* petComponent;
	if (TryGetComponent(eReplicaComponentType::PET, petComponent)) {
		petComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	CharacterComponent* characterComponent;
	if (TryGetComponent(eReplicaComponentType::CHARACTER, characterComponent)) {

		PossessorComponent* possessorComponent;
		if (TryGetComponent(eReplicaComponentType::POSSESSOR, possessorComponent)) {
			possessorComponent->Serialize(outBitStream, bIsInitialUpdate);
		} else {
			// Should never happen, but just to be safe
			outBitStream.Write0();
		}

		LevelProgressionComponent* levelProgressionComponent;
		if (TryGetComponent(eReplicaComponentType::LEVEL_PROGRESSION, levelProgressionComponent)) {
			levelProgressionComponent->Serialize(outBitStream, bIsInitialUpdate);
		} else {
			// Should never happen, but just to be safe
			outBitStream.Write0();
		}

		PlayerForcedMovementComponent* playerForcedMovementComponent;
		if (TryGetComponent(eReplicaComponentType::PLAYER_FORCED_MOVEMENT, playerForcedMovementComponent)) {
			playerForcedMovementComponent->Serialize(outBitStream, bIsInitialUpdate);
		} else {
			// Should never happen, but just to be safe
			outBitStream.Write0();
		}

		characterComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	ItemComponent* itemComponent;
	if (TryGetComponent(eReplicaComponentType::ITEM, itemComponent)) {
		itemComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	InventoryComponent* inventoryComponent;
	if (TryGetComponent(eReplicaComponentType::INVENTORY, inventoryComponent)) {
		inventoryComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	ScriptComponent* scriptComponent;
	if (TryGetComponent(eReplicaComponentType::SCRIPT, scriptComponent)) {
		scriptComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	SkillComponent* skillComponent;
	if (TryGetComponent(eReplicaComponentType::SKILL, skillComponent)) {
		skillComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	BaseCombatAIComponent* baseCombatAiComponent;
	if (TryGetComponent(eReplicaComponentType::BASE_COMBAT_AI, baseCombatAiComponent)) {
		baseCombatAiComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	QuickBuildComponent* quickBuildComponent;
	if (TryGetComponent(eReplicaComponentType::QUICK_BUILD, quickBuildComponent)) {
		DestroyableComponent* destroyableComponent;
		if (TryGetComponent(eReplicaComponentType::DESTROYABLE, destroyableComponent) && !destroyableSerialized) {
			destroyableComponent->Serialize(outBitStream, bIsInitialUpdate);
		}
		destroyableSerialized = true;
		quickBuildComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	MovingPlatformComponent* movingPlatformComponent;
	if (TryGetComponent(eReplicaComponentType::MOVING_PLATFORM, movingPlatformComponent)) {
		movingPlatformComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	SwitchComponent* switchComponent;
	if (TryGetComponent(eReplicaComponentType::SWITCH, switchComponent)) {
		switchComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	VendorComponent* vendorComponent;
	if (TryGetComponent(eReplicaComponentType::VENDOR, vendorComponent)) {
		vendorComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	DonationVendorComponent* donationVendorComponent;
	if (TryGetComponent(eReplicaComponentType::DONATION_VENDOR, donationVendorComponent)) {
		donationVendorComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	AchievementVendorComponent* achievementVendorComponent;
	if (TryGetComponent(eReplicaComponentType::ACHIEVEMENT_VENDOR, achievementVendorComponent)) {
		achievementVendorComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	BouncerComponent* bouncerComponent;
	if (TryGetComponent(eReplicaComponentType::BOUNCER, bouncerComponent)) {
		bouncerComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	ScriptedActivityComponent* scriptedActivityComponent;
	if (TryGetComponent(eReplicaComponentType::SCRIPTED_ACTIVITY, scriptedActivityComponent)) {
		scriptedActivityComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	ShootingGalleryComponent* shootingGalleryComponent;
	if (TryGetComponent(eReplicaComponentType::SHOOTING_GALLERY, shootingGalleryComponent)) {
		shootingGalleryComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	RacingControlComponent* racingControlComponent;
	if (TryGetComponent(eReplicaComponentType::RACING_CONTROL, racingControlComponent)) {
		racingControlComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	LUPExhibitComponent* lupExhibitComponent;
	if (TryGetComponent(eReplicaComponentType::LUP_EXHIBIT, lupExhibitComponent)) {
		lupExhibitComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	ModelComponent* modelComponent;
	if (TryGetComponent(eReplicaComponentType::MODEL, modelComponent)) {
		modelComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	RenderComponent* renderComponent;
	if (TryGetComponent(eReplicaComponentType::RENDER, renderComponent)) {
		renderComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	if (modelComponent || !destroyableSerialized) {
		DestroyableComponent* destroyableComponent;
		if (TryGetComponent(eReplicaComponentType::DESTROYABLE, destroyableComponent) && !destroyableSerialized) {
			destroyableComponent->Serialize(outBitStream, bIsInitialUpdate);
			destroyableSerialized = true;
		}
	}

	MiniGameControlComponent* miniGameControlComponent;
	if (TryGetComponent(eReplicaComponentType::MINI_GAME_CONTROL, miniGameControlComponent)) {
		miniGameControlComponent->Serialize(outBitStream, bIsInitialUpdate);
	}

	// BBB Component, unused currently
	// Need to to write0 so that is serialized correctly
	// TODO: Implement BBB Component
	outBitStream.Write0();
}

void Entity::UpdateXMLDoc(tinyxml2::XMLDocument& doc) {
	//This function should only ever be called from within Character, meaning doc should always exist when this is called.
	//Naturally, we don't include any non-player components in this update function.

	for (const auto& component : m_Components | std::views::values) {
		if (!component) continue;

		component->UpdateXml(doc);
	}
}

void Entity::Update(const float deltaTime) {
	uint32_t timerPosition;
	for (timerPosition = 0; timerPosition < m_Timers.size();) {
		auto& timer = m_Timers[timerPosition];
		timer.Update(deltaTime);
		// If the timer is expired, erase it and dont increment the position because the next timer will be at the same position.
		// Before: [0, 1, 2, 3, ..., n]
		// timerPosition  ^
		// After:  [0, 1, 3, ..., n]
		// timerPosition  ^
		if (timer.GetTime() <= 0) {
			// Remove the timer from the list of timers first so that scripts and events can remove timers without causing iterator invalidation
			auto timerName = timer.GetName();
			m_Timers.erase(m_Timers.begin() + timerPosition);
			GetScript()->OnTimerDone(this, timerName);
			VanityUtilities::OnTimerDone(this, timerName);

			TriggerEvent(eTriggerEventType::TIMER_DONE, this);
		} else {
			// If the timer isnt expired, go to the next timer.
			timerPosition++;
		}
	}

	for (timerPosition = 0; timerPosition < m_CallbackTimers.size(); ) {
		// If the timer is expired, erase it and dont increment the position because the next timer will be at the same position.
		// Before: [0, 1, 2, 3, ..., n]
		// timerPosition  ^
		// After:  [0, 1, 3, ..., n]
		// timerPosition  ^
		auto& callbackTimer = m_CallbackTimers[timerPosition];
		callbackTimer.Update(deltaTime);
		if (callbackTimer.GetTime() <= 0) {
			// Remove the timer from the list of timers first so that callbacks can remove timers without causing iterator invalidation
			auto callback = callbackTimer.GetCallback();
			m_CallbackTimers.erase(m_CallbackTimers.begin() + timerPosition);
			callback();
		} else {
			timerPosition++;
		}
	}

	// Add pending timers to the list of timers so they start next tick.
	if (!m_PendingTimers.empty()) {
		m_Timers.reserve(m_Timers.size() + m_PendingTimers.size());
		m_Timers.insert(m_Timers.end(), m_PendingTimers.begin(), m_PendingTimers.end());
		m_PendingTimers.clear();
	}

	if (!m_PendingCallbackTimers.empty()) {
		m_CallbackTimers.reserve(m_CallbackTimers.size() + m_PendingCallbackTimers.size());
		m_CallbackTimers.insert(m_CallbackTimers.end(), m_PendingCallbackTimers.begin(), m_PendingCallbackTimers.end());
		m_PendingCallbackTimers.clear();
	}

	if (IsSleeping()) {
		if (!m_IsSleeping) {
			Sleep();
			m_IsSleeping = true;
		}

		return;
	} else {
		if (m_IsSleeping) {
			m_IsSleeping = false;
			Wake();
		}
	}


	GetScript()->OnUpdate(this);

	for (const auto& component : m_Components | std::views::values) {
		if (!component) continue;

		component->Update(deltaTime);
	}

	if (m_ShouldDestroyAfterUpdate) {
		Game::entityManager->DestroyEntity(this->GetObjectID());
	}
}

void Entity::OnCollisionProximity(LWOOBJID otherEntity, const std::string& proxName, const std::string& status) {
	Entity* const other = Game::entityManager->GetEntity(otherEntity);
	if (!other) return;

	GetScript()->OnProximityUpdate(this, other, proxName, status);
	VanityUtilities::OnProximityUpdate(this, other, proxName, status);

	auto* const rocketComp = GetComponent<RocketLaunchpadControlComponent>();
	if (!rocketComp) return;

	rocketComp->OnProximityUpdate(other, proxName, status);
}

void Entity::OnCollisionPhantom(const LWOOBJID otherEntity) {
	auto* other = Game::entityManager->GetEntity(otherEntity);
	if (!other) return;

	GetScript()->OnCollisionPhantom(this, other);

	for (const auto& callback : m_PhantomCollisionCallbacks) {
		callback(other);
	}

	SwitchComponent* const switchComp = GetComponent<SwitchComponent>();
	if (switchComp) {
		switchComp->OnUse(other);
	}

	TriggerEvent(eTriggerEventType::ENTER, other);

	// POI system
	const auto& poi = GetVar<std::u16string>(u"POI");

	if (!poi.empty()) {
		auto* missionComponent = other->GetComponent<MissionComponent>();

		if (missionComponent != nullptr) {
			missionComponent->Progress(eMissionTaskType::EXPLORE, 0, 0, GeneralUtils::UTF16ToWTF8(poi));
		}
	}

	if (!other->GetIsDead()) {
		if (GetComponent<BaseCombatAIComponent>() != nullptr) {
			const auto index = std::ranges::find(m_TargetsInPhantom, otherEntity);

			if (index != m_TargetsInPhantom.end()) return;

			m_TargetsInPhantom.push_back(otherEntity);
		}
	}
}

void Entity::OnCollisionLeavePhantom(const LWOOBJID otherEntity) {
	auto* const other = Game::entityManager->GetEntity(otherEntity);
	if (!other) return;

	GetScript()->OnOffCollisionPhantom(this, other);

	TriggerEvent(eTriggerEventType::EXIT, other);

	SwitchComponent* const switchComp = GetComponent<SwitchComponent>();
	if (switchComp) {
		switchComp->EntityLeave(other);
	}

	const auto index = std::ranges::find(m_TargetsInPhantom, otherEntity);

	if (index == m_TargetsInPhantom.end()) return;

	m_TargetsInPhantom.erase(index);
}

void Entity::OnFireEventServerSide(Entity* sender, std::string args, int32_t param1, int32_t param2, int32_t param3) {
	GetScript()->OnFireEventServerSide(this, sender, args, param1, param2, param3);
}

void Entity::OnActivityStateChangeRequest(LWOOBJID senderID, int32_t value1, int32_t value2, const std::u16string& stringValue) {
	GetScript()->OnActivityStateChangeRequest(this, senderID, value1, value2, stringValue);
}

void Entity::OnCinematicUpdate(Entity* self, Entity* sender, eCinematicEvent event, const std::u16string& pathName,
	float_t pathTime, float_t totalTime, int32_t waypoint) {
	GetScript()->OnCinematicUpdate(self, sender, event, pathName, pathTime, totalTime, waypoint);
}

void Entity::NotifyObject(Entity* sender, const std::string& name, int32_t param1, int32_t param2) {
	GameMessages::SendNotifyObject(GetObjectID(), sender->GetObjectID(), GeneralUtils::ASCIIToUTF16(name), UNASSIGNED_SYSTEM_ADDRESS);

	GetScript()->OnNotifyObject(this, sender, name, param1, param2);
}

void Entity::OnEmoteReceived(const int32_t emote, Entity* target) {
	GetScript()->OnEmoteReceived(this, emote, target);
}

void Entity::OnUse(Entity* originator) {
	TriggerEvent(eTriggerEventType::INTERACT, originator);

	GetScript()->OnUse(this, originator);

	for (const auto& component : m_Components | std::views::values) {
		if (!component) continue;

		component->OnUse(originator);
	}
}

void Entity::OnHitOrHealResult(Entity* attacker, int32_t damage) {
	GetScript()->OnHitOrHealResult(this, attacker, damage);
}

void Entity::OnHit(Entity* attacker) {
	TriggerEvent(eTriggerEventType::HIT, attacker);
	GetScript()->OnHit(this, attacker);
}

void Entity::OnZonePropertyEditBegin() {
	GetScript()->OnZonePropertyEditBegin(this);
}

void Entity::OnZonePropertyEditEnd() {
	GetScript()->OnZonePropertyEditEnd(this);
}

void Entity::OnZonePropertyModelEquipped() {
	GetScript()->OnZonePropertyModelEquipped(this);
}

void Entity::OnZonePropertyModelPlaced(Entity* player) {
	GetScript()->OnZonePropertyModelPlaced(this, player);
}

void Entity::OnZonePropertyModelPickedUp(Entity* player) {
	GetScript()->OnZonePropertyModelPickedUp(this, player);
}

void Entity::OnZonePropertyModelRemoved(Entity* player) {
	GetScript()->OnZonePropertyModelRemoved(this, player);
}

void Entity::OnZonePropertyModelRemovedWhileEquipped(Entity* player) {
	GetScript()->OnZonePropertyModelRemovedWhileEquipped(this, player);
}

void Entity::OnZonePropertyModelRotated(Entity* player) {
	GetScript()->OnZonePropertyModelRotated(this, player);
}

void Entity::OnMessageBoxResponse(Entity* sender, int32_t button, const std::u16string& identifier, const std::u16string& userData) {
	GetScript()->OnMessageBoxResponse(this, sender, button, identifier, userData);
}

void Entity::OnChoiceBoxResponse(Entity* sender, int32_t button, const std::u16string& buttonIdentifier, const std::u16string& identifier) {
	GetScript()->OnChoiceBoxResponse(this, sender, button, buttonIdentifier, identifier);
}

void Entity::OnActivityNotify(GameMessages::ActivityNotify& notify) {
	GetScript()->OnActivityNotify(this, notify);
}

void Entity::OnShootingGalleryFire(GameMessages::ShootingGalleryFire& fire) {
	GetScript()->OnShootingGalleryFire(*this, fire);
}

void Entity::OnChildLoaded(GameMessages::ChildLoaded& childLoaded) {
	GetScript()->OnChildLoaded(*this, childLoaded);
}

void Entity::NotifyPlayerResurrectionFinished(GameMessages::PlayerResurrectionFinished& msg) {
	for (const auto& scriptList : m_Subscriptions | std::views::values) {
		auto it = scriptList.find("PlayerResurrectionFinished");
		if (it == scriptList.end()) continue;

		it->second->NotifyPlayerResurrectionFinished(*this, msg);
	}
}

void Entity::RequestActivityExit(Entity* sender, LWOOBJID player, bool canceled) {
	GetScript()->OnRequestActivityExit(sender, player, canceled);
}

CppScripts::Script* const Entity::GetScript() const {
	auto* scriptComponent = GetComponent<ScriptComponent>();
	auto* script = scriptComponent ? scriptComponent->GetScript() : CppScripts::GetInvalidScript();
	DluAssert(script != nullptr);
	return script;
}

void Entity::Smash(const LWOOBJID source, const eKillType killType, const std::u16string& deathType) {
	if (!m_PlayerIsReadyForUpdates) return;

	auto* destroyableComponent = GetComponent<DestroyableComponent>();
	if (destroyableComponent == nullptr) {
		Kill(Game::entityManager->GetEntity(source));
		return;
	}
	auto* possessorComponent = GetComponent<PossessorComponent>();
	if (possessorComponent) {
		if (possessorComponent->GetPossessable() != LWOOBJID_EMPTY) {
			auto* mount = Game::entityManager->GetEntity(possessorComponent->GetPossessable());
			if (mount) possessorComponent->Dismount(mount, true);
		}
	}

	destroyableComponent->Smash(source, killType, deathType);
}

void Entity::Kill(Entity* murderer, const eKillType killType) {
	if (!m_PlayerIsReadyForUpdates) return;

	for (const auto& cb : m_DieCallbacks) {
		cb();
	}

	m_DieCallbacks.clear();

	//お前はもう死んでいる

	GetScript()->OnDie(this, murderer);

	if (m_Spawner != nullptr) {
		m_Spawner->NotifyOfEntityDeath(m_ObjectID);
	}

	if (!IsPlayer()) {
		auto* destroyableComponent = GetComponent<DestroyableComponent>();
		bool waitForDeathAnimation = false;

		if (destroyableComponent) {
			waitForDeathAnimation = !destroyableComponent->GetIsSmashable() && destroyableComponent->GetDeathBehavior() == 0 && killType != eKillType::SILENT;
		}

		// Live waited a hard coded 12 seconds for death animations of type 0 before networking destruction!
		constexpr float DelayDeathTime = 12.0f;
		if (waitForDeathAnimation) AddCallbackTimer(DelayDeathTime, [this]() { Game::entityManager->DestroyEntity(this); });
		else Game::entityManager->DestroyEntity(this);
	}

	const auto& grpNameQBShowBricks = GetVar<std::string>(u"grpNameQBShowBricks");

	if (!grpNameQBShowBricks.empty()) {
		auto spawners = Game::zoneManager->GetSpawnersByName(grpNameQBShowBricks);

		Spawner* spawner = nullptr;

		if (!spawners.empty()) {
			spawner = spawners[0];
		} else {
			spawners = Game::zoneManager->GetSpawnersInGroup(grpNameQBShowBricks);

			if (!spawners.empty()) {
				spawner = spawners[0];
			}
		}

		if (spawner != nullptr) {
			spawner->Spawn();
		}
	}

	// Track a player being smashed
	auto* characterComponent = GetComponent<CharacterComponent>();
	if (characterComponent != nullptr) {
		characterComponent->UpdatePlayerStatistic(TimesSmashed);
	}

	// Track a player smashing something else
	if (murderer != nullptr) {
		auto* murdererCharacterComponent = murderer->GetComponent<CharacterComponent>();
		if (murdererCharacterComponent != nullptr) {
			murdererCharacterComponent->UpdatePlayerStatistic(SmashablesSmashed);
		}
	}
}

void Entity::AddDieCallback(const std::function<void()>& callback) {
	m_DieCallbacks.push_back(callback);
}

void Entity::AddCollisionPhantomCallback(const std::function<void(Entity* target)>& callback) {
	m_PhantomCollisionCallbacks.push_back(callback);
}

void Entity::AddQuickBuildCompleteCallback(const std::function<void(Entity* user)>& callback) const {
	auto* quickBuildComponent = GetComponent<QuickBuildComponent>();
	if (quickBuildComponent != nullptr) {
		quickBuildComponent->AddQuickBuildCompleteCallback(callback);
	}
}

bool Entity::GetIsDead() const {
	DestroyableComponent* dest = GetComponent<DestroyableComponent>();
	return dest && dest->GetArmor() == 0 && dest->GetHealth() == 0;
}

void Entity::AddLootItem(const Loot::Info& info) const {
	if (!IsPlayer()) return;

	auto* const characterComponent = GetComponent<CharacterComponent>();
	if (!characterComponent) return;

	auto& droppedLoot = characterComponent->GetDroppedLoot();
	droppedLoot[info.id] = info;
}

void Entity::PickupItem(const LWOOBJID& objectID) const {
	if (!IsPlayer()) return;
	auto* const inv = GetComponent<InventoryComponent>();
	auto* const characterComponent = GetComponent<CharacterComponent>();
	if (!inv || !characterComponent) return;

	CDObjectsTable* objectsTable = CDClientManager::GetTable<CDObjectsTable>();

	auto& droppedLoot = characterComponent->GetDroppedLoot();

	const auto itr = droppedLoot.find(objectID);

	if (itr != droppedLoot.end()) {
		const auto& info = itr->second;
		auto* const characterComponent = GetComponent<CharacterComponent>();
		if (characterComponent != nullptr) {
			characterComponent->TrackLOTCollection(info.lot);
		}

		const CDObjects& object = objectsTable->GetByID(info.lot);
		if (object.id != 0 && object.type == "Powerup") {
			auto* const skillsTable = CDClientManager::GetTable<CDObjectSkillsTable>();
			const auto skills = skillsTable->Query([&info](CDObjectSkills entry) {return (entry.objectTemplate == info.lot); });
			for (const auto& skill : skills) {
				const auto [skillComponent, missionComponent] = GetComponentsMut<SkillComponent, MissionComponent>();
				if (skillComponent) skillComponent->CastSkill(skill.skillID, GetObjectID(), GetObjectID(), skill.castOnType, NiQuaternion(0, 0, 0, 0));

				if (missionComponent != nullptr) {
					missionComponent->Progress(eMissionTaskType::POWERUP, skill.skillID);
				}
			}
		} else {
			inv->AddItem(info.lot, info.count, eLootSourceType::PICKUP, eInventoryType::INVALID, {}, LWOOBJID_EMPTY, true, false, LWOOBJID_EMPTY, eInventoryType::INVALID, 1);
		}

		droppedLoot.erase(objectID);
	}
}

bool Entity::PickupCoins(uint64_t count) const {
	if (!IsPlayer()) return false;

	auto* const characterComponent = GetComponent<CharacterComponent>();
	if (!characterComponent) return false;

	const auto droppedCoins = characterComponent->GetDroppedCoins();
	if (count > droppedCoins) {
		return false;
	} else {
		characterComponent->SetDroppedCoins(droppedCoins - count);
		return true;
	}
}

void Entity::RegisterCoinDrop(uint64_t count) const {
	if (!IsPlayer()) return;

	auto* const characterComponent = GetComponent<CharacterComponent>();
	if (!characterComponent) return;

	characterComponent->SetDroppedCoins(characterComponent->GetDroppedCoins() + count);
}

void Entity::AddChild(Entity* child) {
	m_IsParentChildDirty = true;
	m_ChildEntities.push_back(child);
}

void Entity::RemoveChild(Entity* child) {
	if (!child) return;
	uint32_t entityPosition = 0;
	while (entityPosition < m_ChildEntities.size()) {
		auto* const childEntity = m_ChildEntities[entityPosition];
		if (!childEntity || childEntity->GetObjectID() == child->GetObjectID()) {
			m_IsParentChildDirty = true;
			m_ChildEntities.erase(m_ChildEntities.begin() + entityPosition);
		} else {
			entityPosition++;
		}
	}
}

void Entity::RemoveParent() {
	this->m_ParentEntity = nullptr;
	m_IsParentChildDirty = true;
}

void Entity::AddTimer(const std::string& name, float time) {
	m_PendingTimers.emplace_back(name, time);
}

void Entity::AddCallbackTimer(float time, const std::function<void()> callback) {
	m_PendingCallbackTimers.emplace_back(time, callback);
}

bool Entity::HasTimer(const std::string& name) {
	return std::find(m_Timers.begin(), m_Timers.end(), name) != m_Timers.end();
}

void Entity::CancelCallbackTimers() {
	m_CallbackTimers.clear();
	m_PendingCallbackTimers.clear();
}

void Entity::ScheduleKillAfterUpdate(Entity* murderer) {
	Game::entityManager->ScheduleForKill(this);

	if (murderer) m_ScheduleKiller = murderer;
}

void Entity::CancelTimer(const std::string& name) {
	for (int i = 0; i < m_Timers.size(); i++) {
		if (m_Timers[i] == name) {
			m_Timers.erase(m_Timers.begin() + i);
			return;
		}
	}
}

void Entity::CancelAllTimers() {
	m_Timers.clear();
	m_PendingTimers.clear();
	m_CallbackTimers.clear();
	m_PendingCallbackTimers.clear();
}

bool Entity::IsPlayer() const {
	return m_TemplateID == 1 && GetSystemAddress() != UNASSIGNED_SYSTEM_ADDRESS;
}

void Entity::TriggerEvent(eTriggerEventType event, Entity* optionalTarget) const {
	auto* const triggerComponent = GetComponent<TriggerComponent>();
	if (triggerComponent) triggerComponent->TriggerEvent(event, optionalTarget);
}

Entity* Entity::GetOwner() const {
	if (m_OwnerOverride != LWOOBJID_EMPTY) {
		auto* other = Game::entityManager->GetEntity(m_OwnerOverride);

		if (other != nullptr) {
			return other->GetOwner();
		}
	}

	return const_cast<Entity*>(this);
}

const NiPoint3& Entity::GetDefaultPosition() const {
	return m_DefaultPosition;
}

const NiQuaternion& Entity::GetDefaultRotation() const {
	return m_DefaultRotation;
}

float Entity::GetDefaultScale() const {
	return m_Scale;
}

void Entity::SetOwnerOverride(const LWOOBJID value) {
	m_OwnerOverride = value;
}

bool Entity::GetIsGhostingCandidate() const {
	return m_IsGhostingCandidate;
}

int8_t Entity::GetObservers() const {
	return m_Observers;
}

void Entity::SetObservers(int8_t value) {
	if (value < 0) {
		value = 0;
	}

	m_Observers = value;
}

void Entity::Sleep() const {
	auto* baseCombatAIComponent = GetComponent<BaseCombatAIComponent>();

	if (baseCombatAIComponent != nullptr) {
		baseCombatAIComponent->Sleep();
	}
}

void Entity::Wake() const {
	auto* baseCombatAIComponent = GetComponent<BaseCombatAIComponent>();

	if (baseCombatAIComponent != nullptr) {
		baseCombatAIComponent->Wake();
	}
}

bool Entity::IsSleeping() const {
	return m_IsGhostingCandidate && m_Observers == 0;
}


NiPoint3 Entity::GetPosition() const {
	GameMessages::GetPosition posMsg{};
	posMsg.pos = NiPoint3Constant::ZERO;
	HandleMsg(posMsg);
	return posMsg.pos;
}

const NiQuaternion& Entity::GetRotation() const {
	auto* controllable = GetComponent<ControllablePhysicsComponent>();

	if (controllable != nullptr) {
		return controllable->GetRotation();
	}

	auto* phantom = GetComponent<PhantomPhysicsComponent>();

	if (phantom != nullptr) {
		return phantom->GetRotation();
	}

	auto* simple = GetComponent<SimplePhysicsComponent>();

	if (simple != nullptr) {
		return simple->GetRotation();
	}

	auto* vehicel = GetComponent<HavokVehiclePhysicsComponent>();

	if (vehicel != nullptr) {
		return vehicel->GetRotation();
	}

	auto* rigidBodyPhantomPhysicsComponent = GetComponent<RigidbodyPhantomPhysicsComponent>();

	if (rigidBodyPhantomPhysicsComponent != nullptr) {
		return rigidBodyPhantomPhysicsComponent->GetRotation();
	}

	return NiQuaternionConstant::IDENTITY;
}

void Entity::SetPosition(const NiPoint3& position) {
	auto* controllable = GetComponent<ControllablePhysicsComponent>();

	if (controllable != nullptr) {
		controllable->SetPosition(position);
	}

	auto* phantom = GetComponent<PhantomPhysicsComponent>();

	if (phantom != nullptr) {
		phantom->SetPosition(position);
	}

	auto* simple = GetComponent<SimplePhysicsComponent>();

	if (simple != nullptr) {
		simple->SetPosition(position);
	}

	auto* vehicel = GetComponent<HavokVehiclePhysicsComponent>();

	if (vehicel != nullptr) {
		vehicel->SetPosition(position);
	}

	auto* rigidBodyPhantomPhysicsComponent = GetComponent<RigidbodyPhantomPhysicsComponent>();

	if (rigidBodyPhantomPhysicsComponent != nullptr) {
		rigidBodyPhantomPhysicsComponent->SetPosition(position);
	}

	Game::entityManager->SerializeEntity(this);
}

void Entity::SetRotation(const NiQuaternion& rotation) {
	auto* controllable = GetComponent<ControllablePhysicsComponent>();

	if (controllable != nullptr) {
		controllable->SetRotation(rotation);
	}

	auto* phantom = GetComponent<PhantomPhysicsComponent>();

	if (phantom != nullptr) {
		phantom->SetRotation(rotation);
	}

	auto* simple = GetComponent<SimplePhysicsComponent>();

	if (simple != nullptr) {
		simple->SetRotation(rotation);
	}

	auto* vehicel = GetComponent<HavokVehiclePhysicsComponent>();

	if (vehicel != nullptr) {
		vehicel->SetRotation(rotation);
	}

	auto* rigidBodyPhantomPhysicsComponent = GetComponent<RigidbodyPhantomPhysicsComponent>();

	if (rigidBodyPhantomPhysicsComponent != nullptr) {
		rigidBodyPhantomPhysicsComponent->SetRotation(rotation);
	}

	Game::entityManager->SerializeEntity(this);
}

void Entity::SetVelocity(const NiPoint3& velocity) {
	auto* controllable = GetComponent<ControllablePhysicsComponent>();

	if (controllable != nullptr) {
		controllable->SetVelocity(velocity);
	}

	auto* simple = GetComponent<SimplePhysicsComponent>();

	if (simple != nullptr) {
		simple->SetVelocity(velocity);
	}

	Game::entityManager->SerializeEntity(this);
}

const NiPoint3& Entity::GetVelocity() const {
	auto* controllable = GetComponent<ControllablePhysicsComponent>();

	if (controllable != nullptr) {
		return controllable->GetVelocity();
	}

	auto* simple = GetComponent<SimplePhysicsComponent>();

	if (simple != nullptr) {
		return simple->GetVelocity();
	}

	return NiPoint3Constant::ZERO;
}

bool Entity::GetBoolean(const std::u16string& name) const {
	return GetVar<bool>(name);
}

int32_t Entity::GetI32(const std::u16string& name) const {
	return GetVar<int32_t>(name);
}

int64_t Entity::GetI64(const std::u16string& name) const {
	return GetVar<int64_t>(name);
}

void Entity::SetBoolean(const std::u16string& name, const bool value) {
	SetVar(name, value);
}

void Entity::SetI32(const std::u16string& name, const int32_t value) {
	SetVar(name, value);
}

void Entity::SetI64(const std::u16string& name, const int64_t value) {
	SetVar(name, value);
}

bool Entity::HasVar(const std::u16string& name) const {
	for (auto* data : m_Settings) {
		if (data->GetKey() == name) {
			return true;
		}
	}

	return false;
}

uint16_t Entity::GetNetworkId() const {
	return m_NetworkID;
}

void Entity::SetNetworkId(const uint16_t id) {
	m_NetworkID = id;
}

std::vector<LWOOBJID> Entity::GetTargetsInPhantom() {
	// Clean up invalid targets, like disconnected players
	m_TargetsInPhantom.erase(std::ranges::remove_if(m_TargetsInPhantom, [](const LWOOBJID id) {
		return !Game::entityManager->GetEntity(id);
		}).begin(), m_TargetsInPhantom.end());

	std::vector<LWOOBJID> enemies;
	for (const auto id : m_TargetsInPhantom) {
		const auto* const combat = GetComponent<BaseCombatAIComponent>();
		if (!combat || !combat->IsEnemy(id)) continue;

		enemies.push_back(id);
	}

	return enemies;
}

void Entity::SendNetworkVar(const std::string& data, const SystemAddress& sysAddr) {
	GameMessages::SendSetNetworkScriptVar(this, sysAddr, data);
}

LDFBaseData* Entity::GetVarData(const std::u16string& name) const {
	for (auto* data : m_Settings) {
		if (data == nullptr) {
			continue;
		}

		if (data->GetKey() != name) {
			continue;
		}

		return data;
	}

	return nullptr;
}

std::string Entity::GetVarAsString(const std::u16string& name) const {
	auto* data = GetVarData(name);
	return data ? data->GetValueAsString() : "";
}

void Entity::Resurrect() {
	if (IsPlayer()) {
		GameMessages::SendResurrect(this);
	}
}

void Entity::AddToGroup(const std::string& group) {
	if (std::ranges::find(m_Groups, group) == m_Groups.end()) {
		m_Groups.push_back(group);
	}
}

void Entity::RetroactiveVaultSize() const {
	auto* const inventoryComponent = GetComponent<InventoryComponent>();
	if (!inventoryComponent) return;

	auto itemsVault = inventoryComponent->GetInventory(eInventoryType::VAULT_ITEMS);
	auto modelVault = inventoryComponent->GetInventory(eInventoryType::VAULT_MODELS);

	if (itemsVault->GetSize() == modelVault->GetSize()) return;

	modelVault->SetSize(itemsVault->GetSize());
}

uint8_t Entity::GetCollectibleID() const {
	auto* collectible = GetComponent<CollectibleComponent>();
	return collectible ? collectible->GetCollectibleId() : 0;
}

void Entity::ProcessPositionUpdate(PositionUpdate& update) {
	if (!IsPlayer()) return;
	auto* controllablePhysicsComponent = GetComponent<ControllablePhysicsComponent>();
	if (!controllablePhysicsComponent) return;

	auto* possessorComponent = GetComponent<PossessorComponent>();
	bool updateChar = true;

	if (possessorComponent) {
		auto* possassableEntity = Game::entityManager->GetEntity(possessorComponent->GetPossessable());

		if (possassableEntity) {
			auto* possessableComponent = possassableEntity->GetComponent<PossessableComponent>();

			// While possessing something, only update char if we are attached to the thing we are possessing
			updateChar = possessableComponent && possessableComponent->GetPossessionType() == ePossessionType::ATTACHED_VISIBLE;

			auto* havokVehiclePhysicsComponent = possassableEntity->GetComponent<HavokVehiclePhysicsComponent>();
			if (havokVehiclePhysicsComponent) {
				havokVehiclePhysicsComponent->SetPosition(update.position);
				havokVehiclePhysicsComponent->SetRotation(update.rotation);
				havokVehiclePhysicsComponent->SetIsOnGround(update.onGround);
				havokVehiclePhysicsComponent->SetIsOnRail(update.onRail);
				havokVehiclePhysicsComponent->SetVelocity(update.velocity);
				havokVehiclePhysicsComponent->SetAngularVelocity(update.angularVelocity);
				havokVehiclePhysicsComponent->SetRemoteInputInfo(update.remoteInputInfo);
			} else {
				// Need to get the mount's controllable physics
				auto* possessedControllablePhysicsComponent = possassableEntity->GetComponent<ControllablePhysicsComponent>();
				if (!possessedControllablePhysicsComponent) return;
				possessedControllablePhysicsComponent->SetPosition(update.position);
				possessedControllablePhysicsComponent->SetRotation(update.rotation);
				possessedControllablePhysicsComponent->SetIsOnGround(update.onGround);
				possessedControllablePhysicsComponent->SetIsOnRail(update.onRail);
				possessedControllablePhysicsComponent->SetVelocity(update.velocity);
				possessedControllablePhysicsComponent->SetAngularVelocity(update.angularVelocity);
			}
			Game::entityManager->SerializeEntity(possassableEntity);
		}
	}

	if (!updateChar) {
		update.velocity = NiPoint3Constant::ZERO;
		update.angularVelocity = NiPoint3Constant::ZERO;
	}

	// Handle statistics
	auto* characterComponent = GetComponent<CharacterComponent>();
	if (characterComponent) {
		characterComponent->TrackPositionUpdate(update.position);
	}

	controllablePhysicsComponent->SetPosition(update.position);
	controllablePhysicsComponent->SetRotation(update.rotation);
	controllablePhysicsComponent->SetIsOnGround(update.onGround);
	controllablePhysicsComponent->SetIsOnRail(update.onRail);
	controllablePhysicsComponent->SetVelocity(update.velocity);
	controllablePhysicsComponent->SetAngularVelocity(update.angularVelocity);

	auto* ghostComponent = GetComponent<GhostComponent>();
	if (ghostComponent) ghostComponent->SetGhostReferencePoint(update.position);
	Game::entityManager->QueueGhostUpdate(GetObjectID());

	if (updateChar) Game::entityManager->SerializeEntity(this);

	OnPlayerPositionUpdate.Notify(this, update);
}

const SystemAddress& Entity::GetSystemAddress() const {
	auto* characterComponent = GetComponent<CharacterComponent>();
	return characterComponent ? characterComponent->GetSystemAddress() : UNASSIGNED_SYSTEM_ADDRESS;
}

const NiPoint3& Entity::GetRespawnPosition() const {
	auto* characterComponent = GetComponent<CharacterComponent>();
	return characterComponent ? characterComponent->GetRespawnPosition() : NiPoint3Constant::ZERO;
}

const NiQuaternion& Entity::GetRespawnRotation() const {
	auto* characterComponent = GetComponent<CharacterComponent>();
	return characterComponent ? characterComponent->GetRespawnRotation() : NiQuaternionConstant::IDENTITY;
}

void Entity::SetRespawnPos(const NiPoint3& position) const {
	auto* characterComponent = GetComponent<CharacterComponent>();
	if (characterComponent) characterComponent->SetRespawnPos(position);
}

void Entity::SetRespawnRot(const NiQuaternion& rotation) const {
	auto* characterComponent = GetComponent<CharacterComponent>();
	if (characterComponent) characterComponent->SetRespawnRot(rotation);
}

int32_t Entity::GetCollisionGroup() const {
	for (const auto* component : m_Components | std::views::values) {
		auto* compToCheck = dynamic_cast<const PhysicsComponent*>(component);
		if (compToCheck) {
			return compToCheck->GetCollisionGroup();
		}
	}

	return 0;
}

bool Entity::HandleMsg(GameMessages::GameMsg& msg) const {
	bool handled = false;
	auto [beg, end] = m_MsgHandlers.equal_range(msg.msgId);
	for (auto& it = beg; it != end; ++it) {
		if (it->second) handled |= it->second(msg);
	}

	return handled;
}

void Entity::RegisterMsg(const MessageType::Game msgId, std::function<bool(GameMessages::GameMsg&)> handler) {
	m_MsgHandlers.emplace(msgId, handler);
}

bool Entity::MsgRequestServerObjectInfo(GameMessages::GameMsg& msg) {
	auto& requestInfo = static_cast<GameMessages::RequestServerObjectInfo&>(msg);
	AMFArrayValue response;
	response.Insert("visible", true);
	response.Insert("objectID", std::to_string(m_ObjectID));
	response.Insert("serverInfo", true);
	GameMessages::GetObjectReportInfo info{};
	info.info = response.InsertArray("data");
	auto& objectInfo = info.info->PushDebug("Object Details");
	auto* table = CDClientManager::GetTable<CDObjectsTable>();

	const auto& objTableInfo = table->GetByID(GetLOT());

	objectInfo.PushDebug<AMFStringValue>("Name") = objTableInfo.name;
	objectInfo.PushDebug<AMFIntValue>("Template ID(LOT)") = GetLOT();
	objectInfo.PushDebug<AMFStringValue>("Object ID") = std::to_string(GetObjectID());
	objectInfo.PushDebug<AMFStringValue>("Spawner's Object ID") = std::to_string(GetSpawnerID());

	auto& componentDetails = objectInfo.PushDebug("Component Information");
	for (const auto [id, component] : m_Components) {
		componentDetails.PushDebug<AMFStringValue>(StringifiedEnum::ToString(id)) = "";
	}

	auto& configData = objectInfo.PushDebug("Config Data");
	for (const auto config : m_Settings) {
		configData.PushDebug<AMFStringValue>(GeneralUtils::UTF16ToWTF8(config->GetKey())) = config->GetValueAsString();

	}
	HandleMsg(info);

	auto* client = Game::entityManager->GetEntity(requestInfo.clientId);
	if (client) GameMessages::SendUIMessageServerToSingleClient("ToggleObjectDebugger", response, client->GetSystemAddress());
	return true;
}
