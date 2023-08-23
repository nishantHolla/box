
#ifndef BOX_H_
#define BOX_H_

#include <bits/stdc++.h>
#include <filesystem>
#include <cstdlib>

#include "sisIO.hpp"

#define LOG_FILE_NAME "boxLog.txt"

class Box {
public:
	Box();

	~Box();

private:
	const std::filesystem::path HOME_DIR = std::filesystem::path(std::getenv("HOME"));
	const std::filesystem::path LOG_FILE = HOME_DIR / LOG_FILE_NAME;

	SisIO io;
};

#endif // !BOX_H_
