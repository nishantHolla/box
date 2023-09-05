
#include "box.hpp"

void Box::prepareTagList(const std::string& _tagString) {
	std::stringstream ss(_tagString);
	std::string tmp;

	while(std::getline(ss, tmp, ',')){
		tagList.push_back(tmp);
	}
}

int Box::addTag(const std::filesystem::path& _path) {

	if (!isBoxxed) {
		io.output(SisIO::messageType::error, ROOT_PATH.string() + " is not boxxed.");
		return 1;
	}

	if (isWrapped) {
		io.output(SisIO::messageType::warn, ROOT_PATH.string() + " is wrapped. Unwrap it to add tags");
		return 2;
	}

	std::filesystem::path filePath = _path;
	if (std::filesystem::exists(_path) == false || std::filesystem::is_regular_file(_path) == false)
		return 1;
	else
		filePath = std::filesystem::canonical(_path);

	std::string selectedTag = io.inputFromSelection("Select tag to add: ", tagList);
	std::vector<std::string> tags = parseTags(filePath);

	if (std::find(tags.begin(), tags.end(), selectedTag) != tags.end())
		return 2;

	const std::string newName = selectedTag + "." + filePath.filename().string();
	std::filesystem::rename(filePath, filePath.parent_path() / newName);

	return 0;
}

int Box::removeTag(const std::filesystem::path& _path) {

	if (!isBoxxed) {
		io.output(SisIO::messageType::error, ROOT_PATH.string() + " is not boxxed.");
		return 1;
	}

	if (isWrapped) {
		io.output(SisIO::messageType::warn, ROOT_PATH.string() + " is wrapped. Unwrap it to remove tags");
		return 2;
	}

	std::filesystem::path filePath = _path;
	if (std::filesystem::exists(_path) == false || std::filesystem::is_regular_file(_path) == false)
		return 1;
	else
		filePath = std::filesystem::canonical(_path);


	std::vector<std::string> tags = parseTags(filePath);
	const std::string FILE_HASH = tags[tags.size()-1];

	// remove file hash section as it is not a tag
	tags.pop_back();

	std::string selectedTag = io.inputFromSelection("Select tag to remove: ", tags);

	tags.erase(std::find(tags.begin(), tags.end(), selectedTag));
	std::string newName = joinTags(tags) + FILE_HASH + _path.extension().string();

	std::filesystem::rename(filePath, filePath.parent_path() / newName);
	return 0;
}

std::vector<std::string> Box::parseTags(const std::filesystem::path& _path) {
	const std::string fileName = _path.stem();

	std::string tmp;
	std::stringstream ss(fileName);
	std::vector<std::string> tags;

	while(getline(ss, tmp, '.'))
		tags.push_back(tmp);

	return tags;
}

std::string Box::joinTags(const std::vector<std::string>& _tags) {
	if (_tags.size() == 0)
		return "";

	std::string result = "";
	for (int i=0, s=_tags.size()-1; i<s; i++) {
		result += (_tags[i] + ".");
	}

	result += _tags[_tags.size()-1];
	return (result + ".");
}
