
#include "box.hpp"
#include <fstream>
#include <cmath>

Box::Box(const std::filesystem::path& _rootPath) :
	ROOT_PATH (_rootPath),
	ignores {".box", ".git"},
	SIMPLE_FLIP_EXTS {".jpg", ".png", ".mp4", ".mp3", ".mkv"},
	flipPathBias (-1),
	io (LOG_FILE)
{
	std::filesystem::remove(LOG_FILE);
}

Box::~Box()
{}
