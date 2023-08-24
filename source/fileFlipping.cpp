
#include "box.hpp"

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
	if (SIMPLE_FLIP_EXTS.find(ext) != SIMPLE_FLIP_EXTS.end())
		singleByteFlip(FILE);

	else
		multyByteFlip(FILE, _filePath);

	FILE.close();
	return 0;
}

int Box::flipAllFilesHelper(const std::filesystem::path& _path) {

	for (auto entry: std::filesystem::recursive_directory_iterator(_path)) {
		if (entry.is_symlink())
			continue;

		if (entry.is_regular_file() == false)
			continue;

		if (pathIsIgnored(entry.path()))
			continue;

		io.output(SisIO::messageType::info, "Flipping flie " + entry.path().string());
		flipFile(entry.path());
	}

	return 0;
}

int Box::flipAllFiles() {
	io.output(SisIO::messageType::info, "Started job: File flipping");
	flipAllFilesHelper(ROOT_PATH);
	io.output(SisIO::messageType::okay, "Finished job: File flipping");
	return 0;
}
