
#include "box.hpp"

bool Box::pathIsIgnored(const std::filesystem::path& _path) {
	bool toSkip = false;
	for (auto& p: _path) {
		if (ignores.find(p.string()) != ignores.end())
			toSkip = true;
	}

	return toSkip;
}

std::filesystem::path Box::pathIsValid(const std::filesystem::path& _path) {
	if (std::filesystem::exists(_path))
		return std::filesystem::canonical(_path);

	return {};
}
