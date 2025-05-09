#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <filesystem>

#include "Pack.h"
#include "PackIndex.h"

enum class eAssetBundleType {
	None,
	Unpacked,
	Packed
};

struct AssetMemoryBuffer : std::streambuf {
	char* m_Base;
	bool m_Success;

	AssetMemoryBuffer(char* base, std::ptrdiff_t n, bool success) {
		m_Base = base;
		m_Success = success;
		if (!m_Success) return;
		this->setg(base, base, base + n);
	}

	~AssetMemoryBuffer() {
		if (m_Success) free(m_Base);
	}

	pos_type seekpos(pos_type sp, std::ios_base::openmode which) override {
		return seekoff(sp - pos_type(off_type(0)), std::ios_base::beg, which);
	}

	pos_type seekoff(off_type off,
		std::ios_base::seekdir dir,
		std::ios_base::openmode which = std::ios_base::in) override {
		if (dir == std::ios_base::cur)
			gbump(off);
		else if (dir == std::ios_base::end)
			setg(eback(), egptr() + off, egptr());
		else if (dir == std::ios_base::beg)
			setg(eback(), eback() + off, egptr());
		return gptr() - eback();
	}
};

struct AssetStream : std::istream {
	AssetStream(char* base, std::ptrdiff_t n, bool success) : std::istream(new AssetMemoryBuffer(base, n, success)) {}

	~AssetStream() {
		delete rdbuf();
	}

	operator bool() {
		return reinterpret_cast<AssetMemoryBuffer*>(rdbuf())->m_Success;
	}
};

class AssetManager {
public:
	AssetManager(const std::filesystem::path& path);

	[[nodiscard]]
	const std::filesystem::path& GetResPath() const {
		return m_ResPath;
	}
	
	[[nodiscard]]
	eAssetBundleType GetAssetBundleType() const {
		return m_AssetBundleType;
	}

	[[nodiscard]]
	bool HasFile(std::string name) const;

	[[nodiscard]]
	bool GetFile(std::string name, char** data, uint32_t* len) const;

	[[nodiscard]]
	AssetStream GetFile(const char* name) const;

private:
	void LoadPackIndex();

	// Modified crc algorithm (mpeg2)
	// Reference: https://stackoverflow.com/questions/54339800/how-to-modify-crc-32-to-crc-32-mpeg-2
	static inline uint32_t crc32b(uint32_t crc, std::string_view message);

	std::filesystem::path m_Path;
	std::filesystem::path m_RootPath;
	std::filesystem::path m_ResPath;

	eAssetBundleType m_AssetBundleType = eAssetBundleType::None;

	std::optional<PackIndex> m_PackIndex;
};
