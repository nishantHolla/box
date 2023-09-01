
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

std::filesystem::path Box::validBoxPath(const std::filesystem::path& _path) {
	std::filesystem::path p = _path;
	while (p.string() != "/") {
		if (std::filesystem::is_directory(p / BOX_DIR))
			return std::filesystem::canonical(_path);

		p = p.parent_path();
	}

	return {};
}

bool Box::authenticateUser(const std::string& _PASSWORD_HASH) {
	for (int i=0; i<5; i++) {
		const std::string attempt = io.input<std::string>("Enter box password: ");
		if (auth.checkHash(attempt, _PASSWORD_HASH))
			return true;

		io.output(SisIO::messageType::error, "Wrong password!");
	}

	return false;
}
