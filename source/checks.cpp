
#include "box.hpp"

bool Box::pathIsIgnored(const std::filesystem::path& _path) {
	bool toSkip = false;
	for (auto& p: _path) {
		if (ignores.find(p.string()) != ignores.end())
			toSkip = true;
	}

	return toSkip;
}
