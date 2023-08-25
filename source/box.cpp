
#include "box.hpp"
#include <fstream>
#include <cmath>

Box::Box(const std::filesystem::path& _rootPath) :
	ROOT_PATH (pathIsValid(_rootPath)),
	BOX_PATH (_rootPath / ".box"),
	BOX_CONFIG_FILE (BOX_PATH / "config"),
	ignores {".box", ".git"},
	SIMPLE_FLIP_EXTS {".jpg", ".png", ".mp4", ".mp3", ".mkv"},
	io (LOG_FILE),
	auth ()
{
	// remove previous log file if exists.
	std::filesystem::remove(LOG_FILE);

	if (ROOT_PATH.empty()) {
		io.output(SisIO::messageType::error, "Invalid root " + _rootPath.string());
		std::exit(1);
	}

	isBoxxed = std::filesystem::is_directory(BOX_PATH);
	if (isBoxxed) {
		std::fstream CONFIG_FILE (BOX_CONFIG_FILE, std::ios::in);
		if (!CONFIG_FILE) {
			io.output(SisIO::messageType::error, "Failed to open box config file at " + BOX_PATH.string());
			std::exit(2);
		}

		std::string passwordHashTitle;
		std::string passwordHashResult;
		std::string isWrappedTitle;
		std::string isWrappedResult;

		CONFIG_FILE >> passwordHashTitle >> passwordHashResult;
		CONFIG_FILE >> isWrappedTitle >> isWrappedResult;

		isWrapped = (isWrappedResult == "true");
		PASSWORD_HASH = passwordHashResult;
	}

	io.outputLevel = SisIO::messageType::prompt;
}

int Box::wrap() {
	if (!isBoxxed) {
		io.output(SisIO::messageType::error, ROOT_PATH.string() + " is not boxxed.");
		return 1;
	}

	if (isWrapped) {
		io.output(SisIO::messageType::warn, ROOT_PATH.string() + " is already wrapped.");
		return 2;
	}

	if (!authenticateUser(PASSWORD_HASH)) {
		io.output(SisIO::messageType::error, "Too many failed attempts to authenticate. Terminating call.");
		return 3;
	}

	flipAllFiles();
	flipAllPaths();
	isWrapped = true;

	return 0;
}

int Box::create() {
	if (isBoxxed) {
		io.output(SisIO::messageType::error, ROOT_PATH.string() + " is already boxxed.");
		return 1;
	}

	const std::string PASSWORD = io.input<std::string>("Enter a password for the box: ");
	const std::string pHash = auth.generateHash(PASSWORD);

	std::filesystem::create_directory(BOX_PATH);
	
	std::fstream CONFIG_FILE (BOX_CONFIG_FILE, std::ios::out);
	if (!CONFIG_FILE) {
		io.log(SisIO::messageType::error, "Failed to create box config file at " + BOX_PATH.string(), "box create method");
		return 2;
	}

	CONFIG_FILE << "password " << pHash << "\n";
	CONFIG_FILE << "isWrapped " << "false" << "\n";

	PASSWORD_HASH = pHash;
	isBoxxed = true;
	isWrapped = false;

	CONFIG_FILE.close();
	io.output(SisIO::messageType::okay, "Created box at " + ROOT_PATH.string());
	return 0;
}

int Box::unwrap() {
	if (!isBoxxed) {
		io.output(SisIO::messageType::error, ROOT_PATH.string() + " is not boxxed.");
		return 1;
	}

	if (!isWrapped) {
		io.output(SisIO::messageType::warn, ROOT_PATH.string() + " is already unwrapped.");
		return 2;
	}

	if (!authenticateUser(PASSWORD_HASH)) {
		io.output(SisIO::messageType::error, "Too many failed attempts to authenticate. Terminating call.");
		return 3;
	}

	flipAllPaths();
	flipAllFiles();
	isWrapped = false;

	return 0;
}

Box::~Box()
{
	if (!isBoxxed)
		return;

	std::fstream CONFIG_FILE (BOX_CONFIG_FILE, std::ios::out);
	if (!CONFIG_FILE) {
		io.log(SisIO::messageType::error, "Failed to update box config file at " + BOX_PATH.string(), "box destructor method");
		return;
	}

	const std::string isWrappedString = isWrapped ? "true" : "false";
	CONFIG_FILE << "password " << PASSWORD_HASH << "\n";
	CONFIG_FILE << "isWrapped " << isWrappedString << "\n";

	CONFIG_FILE.close();
}
