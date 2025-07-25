#pragma once

#include <map>
#include <functional>
#include <tuple>
#include <typeinfo>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include "NiPoint3.h"
#include "NiQuaternion.h"
#include "LDFFormat.h"
#include "eKillType.h"
#include "Observable.h"

namespace GameMessages {
	struct GameMsg;
	struct ActivityNotify;
	struct ShootingGalleryFire;
	struct ChildLoaded;
	struct PlayerResurrectionFinished;
};

namespace MessageType {
	enum class Game : uint16_t;
}

namespace Loot {
	class Info;
};

namespace tinyxml2 {
	class XMLDocument;
};

class Player;
class User;
class Spawner;
class ScriptComponent;
class dpEntity;
class EntityTimer;
class Component;
class Item;
class Character;
class EntityCallbackTimer;
class PositionUpdate;
struct EntityInfo;
enum class eTriggerEventType;
enum class eGameMasterLevel : uint8_t;
enum class eReplicaComponentType : uint32_t;
enum class eReplicaPacketType : uint8_t;
enum class eCinematicEvent : uint32_t;

namespace CppScripts {
	class Script;
};

/**
 * An entity in the world. Has multiple components.
 */
class Entity {
public:
	Entity(const LWOOBJID& objectID, const EntityInfo& info, User* parentUser = nullptr, Entity* parentEntity = nullptr);
	~Entity();

	void Initialize();

	bool operator==(const Entity& other) const;
	bool operator!=(const Entity& other) const;

	/**
	 * Getters
	 */

	const LWOOBJID& GetObjectID() const { return m_ObjectID; }

	const LOT GetLOT() const { return m_TemplateID; }

	Character* GetCharacter() const { return m_Character; }

	eGameMasterLevel GetGMLevel() const { return m_GMLevel; }

	uint8_t GetCollectibleID() const;

	Entity* GetParentEntity() const { return m_ParentEntity; }

	std::vector<std::string>& GetGroups() { return m_Groups; };

	Spawner* GetSpawner() const { return m_Spawner; }

	LWOOBJID GetSpawnerID() const { return m_SpawnerID; }

	const std::vector<LDFBaseData*>& GetSettings() const { return m_Settings; }

	const std::vector<LDFBaseData*>& GetNetworkSettings() const { return m_NetworkSettings; }

	bool GetIsDead() const;

	bool GetPlayerReadyForUpdates() const { return m_PlayerIsReadyForUpdates; }

	bool GetIsGhostingCandidate() const;
	void SetIsGhostingCandidate(bool value) { m_IsGhostingCandidate = value; };

	int8_t GetObservers() const;

	uint16_t GetNetworkId() const;

	Entity* GetOwner() const;

	const NiPoint3& GetDefaultPosition() const;

	const NiQuaternion& GetDefaultRotation() const;

	float GetDefaultScale() const;

	NiPoint3 GetPosition() const;

	const NiQuaternion& GetRotation() const;

	const SystemAddress& GetSystemAddress() const;

	// Returns the collision group for this entity.
	// Because the collision group is stored on a base component, this will look for a physics component
	// then return the collision group from that.
	int32_t GetCollisionGroup() const;

	const NiPoint3& GetVelocity() const;

	/**
	 * Setters
	 */

	void SetCharacter(Character* value) { m_Character = value; }

	void SetGMLevel(eGameMasterLevel value);

	void SetOwnerOverride(LWOOBJID value);

	void SetPlayerReadyForUpdates() { m_PlayerIsReadyForUpdates = true; }

	void SetObservers(int8_t value);

	void SetNetworkId(uint16_t id);

	void SetPosition(const NiPoint3& position);

	void SetRotation(const NiQuaternion& rotation);

	void SetRespawnPos(const NiPoint3& position) const;

	void SetRespawnRot(const NiQuaternion& rotation) const;

	void SetVelocity(const NiPoint3& velocity);

	/**
	 * Component management
	 */

	Component* GetComponent(eReplicaComponentType componentID) const;

	template<typename T>
	T* GetComponent() const;

	template<typename... T>
	auto GetComponents() const;

	template<typename... T>
	auto GetComponentsMut() const;

	template<typename T>
	bool TryGetComponent(eReplicaComponentType componentId, T*& component) const;

	bool HasComponent(eReplicaComponentType componentId) const;

	void AddComponent(eReplicaComponentType componentId, Component* component);

	bool MsgRequestServerObjectInfo(GameMessages::GameMsg& msg);

	// This is expceted to never return nullptr, an assert checks this.
	CppScripts::Script* const GetScript() const;

	void Subscribe(LWOOBJID scriptObjId, CppScripts::Script* scriptToAdd, const std::string& notificationName);
	void Unsubscribe(LWOOBJID scriptObjId, const std::string& notificationName);

	void SetProximityRadius(float proxRadius, std::string name);
	void SetProximityRadius(dpEntity* entity, std::string name);

	void AddChild(Entity* child);
	void RemoveChild(Entity* child);
	void RemoveParent();

	// Adds a timer to start next frame with the given name and time.
	void AddTimer(const std::string& name, float time);
	void AddCallbackTimer(float time, const std::function<void()> callback);
	bool HasTimer(const std::string& name);
	void CancelCallbackTimers();
	void CancelAllTimers();
	void CancelTimer(const std::string& name);

	void AddToGroup(const std::string& group);
	bool IsPlayer() const;

	std::unordered_map<eReplicaComponentType, Component*>& GetComponents() { return m_Components; } // TODO: Remove

	void WriteBaseReplicaData(RakNet::BitStream& outBitStream, eReplicaPacketType packetType);
	void WriteComponents(RakNet::BitStream& outBitStream, eReplicaPacketType packetType) const;
	void UpdateXMLDoc(tinyxml2::XMLDocument& doc);
	void Update(float deltaTime);

	// Events
	void OnCollisionProximity(LWOOBJID otherEntity, const std::string& proxName, const std::string& status);
	void OnCollisionPhantom(LWOOBJID otherEntity);
	void OnCollisionLeavePhantom(LWOOBJID otherEntity);

	void OnFireEventServerSide(Entity* sender, std::string args, int32_t param1 = -1, int32_t param2 = -1, int32_t param3 = -1);
	void OnActivityStateChangeRequest(const LWOOBJID senderID, const int32_t value1, const int32_t value2,
		const std::u16string& stringValue);
	void OnCinematicUpdate(Entity* self, Entity* sender, eCinematicEvent event, const std::u16string& pathName,
		float_t pathTime, float_t totalTime, int32_t waypoint);

	void NotifyObject(Entity* sender, const std::string& name, int32_t param1 = 0, int32_t param2 = 0);
	void OnEmoteReceived(int32_t emote, Entity* target);

	void OnUse(Entity* originator);

	void OnHitOrHealResult(Entity* attacker, int32_t damage);
	void OnHit(Entity* attacker);

	void OnZonePropertyEditBegin();
	void OnZonePropertyEditEnd();
	void OnZonePropertyModelEquipped();
	void OnZonePropertyModelPlaced(Entity* player);
	void OnZonePropertyModelPickedUp(Entity* player);
	void OnZonePropertyModelRemoved(Entity* player);
	void OnZonePropertyModelRemovedWhileEquipped(Entity* player);
	void OnZonePropertyModelRotated(Entity* player);
	void OnActivityNotify(GameMessages::ActivityNotify& notify);
	void OnShootingGalleryFire(GameMessages::ShootingGalleryFire& notify);
	void OnChildLoaded(GameMessages::ChildLoaded& childLoaded);
	void NotifyPlayerResurrectionFinished(GameMessages::PlayerResurrectionFinished& msg);

	void OnMessageBoxResponse(Entity* sender, int32_t button, const std::u16string& identifier, const std::u16string& userData);
	void OnChoiceBoxResponse(Entity* sender, int32_t button, const std::u16string& buttonIdentifier, const std::u16string& identifier);
	void RequestActivityExit(Entity* sender, LWOOBJID player, bool canceled);

	void Smash(const LWOOBJID source = LWOOBJID_EMPTY, const eKillType killType = eKillType::VIOLENT, const std::u16string& deathType = u"");
	void Kill(Entity* murderer = nullptr, const eKillType killType = eKillType::SILENT);
	void AddQuickBuildCompleteCallback(const std::function<void(Entity* user)>& callback) const;
	void AddCollisionPhantomCallback(const std::function<void(Entity* target)>& callback);
	void AddDieCallback(const std::function<void()>& callback);
	void Resurrect();

	void AddLootItem(const Loot::Info& info) const;
	void PickupItem(const LWOOBJID& objectID) const;

	bool PickupCoins(uint64_t count) const;
	void RegisterCoinDrop(uint64_t count) const;

	void ScheduleKillAfterUpdate(Entity* murderer = nullptr);
	void TriggerEvent(eTriggerEventType event, Entity* optionalTarget = nullptr) const;
	void ScheduleDestructionAfterUpdate() { m_ShouldDestroyAfterUpdate = true; }

	const NiPoint3& GetRespawnPosition() const;
	const NiQuaternion& GetRespawnRotation() const;

	void Sleep() const;
	void Wake() const;
	bool IsSleeping() const;

	/*
	 * Utility
	 */
	 /**
	  * Retroactively corrects the model vault size due to incorrect initialization in a previous patch.
	  *
	  */
	void RetroactiveVaultSize() const;
	bool GetBoolean(const std::u16string& name) const;
	int32_t GetI32(const std::u16string& name) const;
	int64_t GetI64(const std::u16string& name) const;

	void SetBoolean(const std::u16string& name, bool value);
	void SetI32(const std::u16string& name, int32_t value);
	void SetI64(const std::u16string& name, int64_t value);

	bool HasVar(const std::u16string& name) const;

	template<typename T>
	const T& GetVar(const std::u16string& name) const;

	template<typename T>
	void SetVar(const std::u16string& name, T value);

	void SendNetworkVar(const std::string& data, const SystemAddress& sysAddr);

	template<typename T>
	void SetNetworkVar(const std::u16string& name, T value, const SystemAddress& sysAddr = UNASSIGNED_SYSTEM_ADDRESS);

	template<typename T>
	void SetNetworkVar(const std::u16string& name, std::vector<T> value, const SystemAddress& sysAddr = UNASSIGNED_SYSTEM_ADDRESS);

	template<typename T>
	T GetNetworkVar(const std::u16string& name);

	/**
	 * Get the LDF value and cast it as T.
	 */
	template<typename T>
	T GetVarAs(const std::u16string& name) const;

	template<typename ComponentType, typename... VaArgs>
	ComponentType* AddComponent(VaArgs... args);

	/**
	 * Get the LDF data.
	 */
	LDFBaseData* GetVarData(const std::u16string& name) const;

	/**
	 * Get the LDF value and convert it to a string.
	 */
	std::string GetVarAsString(const std::u16string& name) const;

	/*
	 * Collision
	 */
	std::vector<LWOOBJID> GetTargetsInPhantom();

	Entity* GetScheduledKiller() { return m_ScheduleKiller; }

	void ProcessPositionUpdate(PositionUpdate& update);

	// Scale will only be communicated to the client when the construction packet is sent
	void SetScale(const float scale) { m_Scale = scale; };

	void RegisterMsg(const MessageType::Game msgId, std::function<bool(GameMessages::GameMsg&)> handler);

	bool HandleMsg(GameMessages::GameMsg& msg) const;

	void RegisterMsg(const MessageType::Game msgId, auto* self, const auto handler) {
		RegisterMsg(msgId, std::bind(handler, self, std::placeholders::_1));
	}

	/**
	 * @brief The observable for player entity position updates.
	 */
	static Observable<Entity*, const PositionUpdate&> OnPlayerPositionUpdate;

private:
	void WriteLDFData(const std::vector<LDFBaseData*>& ldf, RakNet::BitStream& outBitStream) const;
	LWOOBJID m_ObjectID;

	LOT m_TemplateID;

	std::vector<LDFBaseData*> m_Settings;
	std::vector<LDFBaseData*> m_NetworkSettings;

	NiPoint3 m_DefaultPosition;
	NiQuaternion m_DefaultRotation;
	float m_Scale;

	Spawner* m_Spawner;
	LWOOBJID m_SpawnerID;

	bool m_HasSpawnerNodeID;
	uint32_t m_SpawnerNodeID;

	Character* m_Character;

	Entity* m_ParentEntity; //For spawners and the like
	std::vector<Entity*> m_ChildEntities;
	eGameMasterLevel m_GMLevel;
	std::vector<std::string> m_Groups;
	uint16_t m_NetworkID;
	std::vector<std::function<void()>> m_DieCallbacks;
	std::vector<std::function<void(Entity* target)>> m_PhantomCollisionCallbacks;

	std::unordered_map<eReplicaComponentType, Component*> m_Components;
	std::vector<EntityTimer> m_Timers;
	std::vector<EntityTimer> m_PendingTimers;
	std::vector<EntityCallbackTimer> m_CallbackTimers;
	std::vector<EntityCallbackTimer> m_PendingCallbackTimers;

	bool m_ShouldDestroyAfterUpdate = false;

	LWOOBJID m_OwnerOverride;

	Entity* m_ScheduleKiller;

	bool m_PlayerIsReadyForUpdates = false;

	bool m_IsGhostingCandidate = false;

	int8_t m_Observers = 0;

	bool m_IsParentChildDirty = true;

	bool m_IsSleeping = false;

	/*
	 * Collision
	 */
	std::vector<LWOOBJID> m_TargetsInPhantom;

	// objectID of receiver and map of notification name to script
	std::map<LWOOBJID, std::map<std::string, CppScripts::Script*>> m_Subscriptions;

	std::unordered_multimap<MessageType::Game, std::function<bool(GameMessages::GameMsg&)>> m_MsgHandlers;
};

/**
 * Template definitions.
 */

template<typename T>
bool Entity::TryGetComponent(const eReplicaComponentType componentId, T*& component) const {
	const auto& index = m_Components.find(componentId);

	if (index == m_Components.end()) {
		component = nullptr;

		return false;
	}

	component = dynamic_cast<T*>(index->second);

	return true;
}

template <typename T>
T* Entity::GetComponent() const {
	return dynamic_cast<T*>(GetComponent(T::ComponentType));
}


template<typename T>
const T& Entity::GetVar(const std::u16string& name) const {
	auto* data = GetVarData(name);

	if (data == nullptr) {
		return LDFData<T>::Default;
	}

	auto* typed = dynamic_cast<LDFData<T>*>(data);

	if (typed == nullptr) {
		return LDFData<T>::Default;
	}

	return typed->GetValue();
}

template<typename T>
T Entity::GetVarAs(const std::u16string& name) const {
	const auto data = GetVarAsString(name);

	return GeneralUtils::TryParse<T>(data).value_or(LDFData<T>::Default);
}

template<typename T>
void Entity::SetVar(const std::u16string& name, T value) {
	auto* data = GetVarData(name);

	if (data == nullptr) {
		auto* data = new LDFData<T>(name, value);

		m_Settings.push_back(data);

		return;
	}

	auto* typed = dynamic_cast<LDFData<T>*>(data);

	if (typed == nullptr) {
		return;
	}

	typed->SetValue(value);
}

template<typename T>
void Entity::SetNetworkVar(const std::u16string& name, T value, const SystemAddress& sysAddr) {
	LDFData<T>* newData = nullptr;

	for (auto* data : m_NetworkSettings) {
		if (data->GetKey() != name)
			continue;

		newData = dynamic_cast<LDFData<T>*>(data);
		if (newData != nullptr) {
			newData->SetValue(value);
		} else {  // If we're changing types
			m_NetworkSettings.erase(
				std::remove(m_NetworkSettings.begin(), m_NetworkSettings.end(), data), m_NetworkSettings.end()
			);
			delete data;
		}

		break;
	}

	if (newData == nullptr) {
		newData = new LDFData<T>(name, value);
	}

	m_NetworkSettings.push_back(newData);
	SendNetworkVar(newData->GetString(true), sysAddr);
}

template<typename T>
void Entity::SetNetworkVar(const std::u16string& name, std::vector<T> values, const SystemAddress& sysAddr) {
	std::stringstream updates;
	auto index = 1;

	for (const auto& value : values) {
		LDFData<T>* newData = nullptr;
		const auto& indexedName = name + u"." + GeneralUtils::to_u16string(index);

		for (auto* data : m_NetworkSettings) {
			if (data->GetKey() != indexedName)
				continue;

			newData = dynamic_cast<LDFData<T>*>(data);
			newData->SetValue(value);
			break;
		}

		if (newData == nullptr) {
			newData = new LDFData<T>(indexedName, value);
		}

		m_NetworkSettings.push_back(newData);

		if (index == values.size()) {
			updates << newData->GetString(true);
		} else {
			updates << newData->GetString(true) << "\n";
		}

		index++;
	}

	SendNetworkVar(updates.str(), sysAddr);
}

template<typename T>
T Entity::GetNetworkVar(const std::u16string& name) {
	for (auto* data : m_NetworkSettings) {
		if (data == nullptr || data->GetKey() != name)
			continue;

		auto* typed = dynamic_cast<LDFData<T>*>(data);
		if (typed == nullptr)
			continue;

		return typed->GetValue();
	}

	return LDFData<T>::Default;
}

/**
 * @brief Adds a component of type ComponentType to this entity and forwards the arguments to the constructor.
 *
 * @tparam ComponentType The component class type to add. Must derive from Component.
 * @tparam VaArgs The argument types to forward to the constructor.
 * @param args The arguments to forward to the constructor. The first argument passed to the ComponentType constructor will be this entity.
 * @return ComponentType* The added component. Will never return null.
 */
template<typename ComponentType, typename... VaArgs>
inline ComponentType* Entity::AddComponent(VaArgs... args) {
	static_assert(std::is_base_of_v<Component, ComponentType>, "ComponentType must be a Component");

	// Get the component if it already exists, or default construct a nullptr
	auto*& componentToReturn = m_Components[ComponentType::ComponentType];

	// If it doesn't exist, create it and forward the arguments to the constructor
	if (!componentToReturn) {
		componentToReturn = new ComponentType(this, std::forward<VaArgs>(args)...);
	} else {
		// In this case the block is already allocated and ready for use
		// so we use a placement new to construct the component again as was requested by the caller.
		// Placement new means we already have memory allocated for the object, so this just calls its constructor again.
		// This is useful for when we want to create a new object in the same memory location as an old one.
		componentToReturn->~Component();
		new(componentToReturn) ComponentType(this, std::forward<VaArgs>(args)...);
	}

	// Finally return the created or already existing component.
	// Because of the assert above, this should always be a ComponentType* but I need a way to guarantee the map cannot be modifed outside this function
	// To allow a static cast here instead of a dynamic one.
	return dynamic_cast<ComponentType*>(componentToReturn);
}

template<typename... T>
auto Entity::GetComponents() const {
	return GetComponentsMut<const T...>();
}

template<typename... T>
auto Entity::GetComponentsMut() const {
	return std::tuple{GetComponent<T>()...};
}
