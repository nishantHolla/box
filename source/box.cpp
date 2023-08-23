
#include "box.hpp"
#include <fstream>
#include <cmath>

Box::Box() :
	SIMPLE_FLIP_EXTS {".jpg", ".png", ".mp4", ".mp3", ".mkv"},
	io (LOG_FILE)
{
	std::filesystem::remove(LOG_FILE);

}

void Box::singleByteFlip(std::fstream& _stream) {
	char c;

	_stream.seekg(std::ios::beg);
	_stream.read(&c, 1);

	c = c ^ FLIP_FILE_KEY;

	_stream.seekp(std::ios::beg);
	_stream.write(&c, 1);
}

void Box::multyByteFlip(std::fstream& _stream, const std::filesystem::path& _filePath) {
	const int FILE_SIZE = std::filesystem::file_size(_filePath);
	char *fileData = new char[FILE_SIZE];

	_stream.seekg(std::ios::beg);
	for (int i=0; i<FILE_SIZE; i++) {
		char c;
		_stream.read(&c, 1);
		fileData[i] = (c ^ FLIP_FILE_KEY);
	}

	_stream.seekp(std::ios::beg);
	for (int i=0; i<FILE_SIZE; i++) {
		_stream.write(&(fileData[i]), 1);
	}

	delete[] fileData;
}

int Box::flipFile(const std::filesystem::path& _filePath) {

	if (std::filesystem::is_regular_file(_filePath) == false) {
		io.log( SisIO::messageType::error,
			"Could not flip non existent file " + _filePath.string(),
			"flipFile method"
		);
		return 1;
	}

	std::fstream FILE (_filePath, std::ios_base::binary | std::ios_base::out | std::ios_base::in);

	if (!FILE || !FILE.good()) {
		io.log( SisIO::messageType::error,
			"Could not open file " + _filePath.string() + " for flipping",
			"flipFile method"
		);
		return 2;
	}

	const std::string ext = _filePath.extension().string();
	if ( std::find(SIMPLE_FLIP_EXTS.begin(), SIMPLE_FLIP_EXTS.end(), ext) != SIMPLE_FLIP_EXTS.end() )
		singleByteFlip(FILE);

	else
		multyByteFlip(FILE, _filePath);

	FILE.close();
	return 0;
}

int Box::flipPath(const std::filesystem::path& _path, const int _bias) {

	if (std::filesystem::exists(_path) == false) {
		io.log(SisIO::messageType::error,
			"Could not flip non existent path " + _path.string(),
			"flipPath method"
		);
		return 1;
	}

	const std::filesystem::path path = std::filesystem::canonical(_path);
	const std::filesystem::path parentPath = path.parent_path();
	const std::string baseName = path.filename();
	std::string newName = "";

	for (int i=0, s=baseName.size(); i<s; i++) {
		if (baseName[i] < 'A' || baseName[i] > 'z') {
			newName += baseName[i];
			continue;
		}

		int key = FLIP_PATH_ODD_KEY;
		if (i % 2 == 0)
			key = FLIP_PATH_EVEN_KEY;

		key = std::abs(key - _bias);

		if (baseName[i] >= 'A' && baseName[i] <= 'Z')
			newName += ((baseName[i] + key - 'A') % 26 + 'A');
		else
			newName += ((baseName[i] + key - 'a') % 26 + 'a');
	}

	std::cout << baseName << " -> " << newName;

	return 0;
}

Box::~Box()
{}
