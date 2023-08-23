
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

#define ANSI_MOVE_UP "\033[A"
#define ANSI_CLEAR_LINE "\33[2K"

class Box {
private:
	class Informer {
	public:
		Informer(SisIO *_io);

		void beginSection(const std::string& _sectionName, const int _targetCount);
		void progress(const std::string& _message);
		void endSection();

		~Informer();
	private:

		SisIO *io;
		int currentCount;
		int targetCount;
		bool inSection;
	};

	const std::filesystem::path HOME_DIR = std::filesystem::path(std::getenv("HOME"));
	const std::filesystem::path LOG_FILE = HOME_DIR / LOG_FILE_NAME;
	const std::vector<const char *> SIMPLE_FLIP_EXTS;

	int flipFile(const std::filesystem::path& _filePath);
	void singleByteFlip(std::fstream& _stream);
	void multyByteFlip(std::fstream& _stream, const std::filesystem::path& _filePath);

	int flipPath(const std::filesystem::path& _path, const int _bias);


	SisIO io;

public:
	Box();
	Informer informer;

	~Box();
};

#endif // !BOX_H_
