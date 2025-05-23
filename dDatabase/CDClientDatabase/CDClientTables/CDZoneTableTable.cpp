#include "CDZoneTableTable.h"

namespace CDZoneTableTable {
	Table entries;

	void LoadValuesFromDatabase() {
		// Get the data from the database
		auto tableData = CDClientDatabase::ExecuteQuery("SELECT * FROM ZoneTable");
		while (!tableData.eof()) {
			CDZoneTable entry;
			entry.zoneID = tableData.getIntField("zoneID", -1);
			entry.locStatus = tableData.getIntField("locStatus", -1);
			entry.zoneName = tableData.getStringField("zoneName", "");
			entry.scriptID = tableData.getIntField("scriptID", -1);
			entry.ghostdistance_min = tableData.getFloatField("ghostdistance_min", -1.0f);
			entry.ghostdistance = tableData.getFloatField("ghostdistance", -1.0f);
			entry.population_soft_cap = tableData.getIntField("population_soft_cap", -1);
			entry.population_hard_cap = tableData.getIntField("population_hard_cap", -1);
			UNUSED(entry.DisplayDescription = tableData.getStringField("DisplayDescription", ""));
			UNUSED(entry.mapFolder = tableData.getStringField("mapFolder", ""));
			entry.smashableMinDistance = tableData.getFloatField("smashableMinDistance", -1.0f);
			entry.smashableMaxDistance = tableData.getFloatField("smashableMaxDistance", -1.0f);
			UNUSED(entry.mixerProgram = tableData.getStringField("mixerProgram", ""));
			UNUSED(entry.clientPhysicsFramerate = tableData.getStringField("clientPhysicsFramerate", ""));
			entry.serverPhysicsFramerate = tableData.getStringField("serverPhysicsFramerate", "");
			entry.zoneControlTemplate = tableData.getIntField("zoneControlTemplate", -1);
			entry.widthInChunks = tableData.getIntField("widthInChunks", -1);
			entry.heightInChunks = tableData.getIntField("heightInChunks", -1);
			entry.petsAllowed = tableData.getIntField("petsAllowed", -1) == 1 ? true : false;
			entry.localize = tableData.getIntField("localize", -1) == 1 ? true : false;
			entry.fZoneWeight = tableData.getFloatField("fZoneWeight", -1.0f);
			UNUSED(entry.thumbnail = tableData.getStringField("thumbnail", ""));
			entry.PlayerLoseCoinsOnDeath = tableData.getIntField("PlayerLoseCoinsOnDeath", -1) == 1 ? true : false;
			entry.disableSaveLoc = tableData.getIntField("disableSaveLoc", -1) == 1 ? true : false;
			entry.teamRadius = tableData.getFloatField("teamRadius", -1.0f);
			UNUSED(entry.gate_version = tableData.getStringField("gate_version", ""));
			entry.mountsAllowed = tableData.getIntField("mountsAllowed", -1) == 1 ? true : false;

			entries[entry.zoneID] = entry;
			tableData.nextRow();
		}
	}

	//! Queries the table with a zoneID to find.
	const CDZoneTable* Query(uint32_t zoneID) {
		const auto& iter = entries.find(zoneID);
		if (iter != entries.end()) {
			return &iter->second;
		}

		return nullptr;
	}
}
