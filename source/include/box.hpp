
#ifndef BOX_H_
#define BOX_H_

#include <bits/stdc++.h>
#include <filesystem>
#include <cstdlib>
#include <vector>

#include "sisIO.hpp"

#define LOG_FILE_NAME "boxLog.txt"

#define FLIP_FILE_KEY 128

#define FLIP_PATH_ODD_KEY 3
#define FLIP_PATH_EVEN_KEY 8
#define FLIP_PATH_UNWRAP_BIAS 26
#define FLIP_PATH_WRAP_BIAS 0

class Box {
public:
	Box();

	~Box();

private:

	const std::filesystem::path HOME_DIR = std::filesystem::path(std::getenv("HOME"));
	const std::filesystem::path LOG_FILE = HOME_DIR / LOG_FILE_NAME;
	const std::vector<const char *> SIMPLE_FLIP_EXTS;

	int flipFile(const std::filesystem::path& _filePath);
	void singleByteFlip(std::fstream& _stream);
	void multyByteFlip(std::fstream& _stream, const std::filesystem::path& _filePath);

	int flipPath(const std::filesystem::path& _path, const int _bias);

	SisIO io;
};

#endif // !BOX_H_
