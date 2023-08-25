
#include "sisAuth.hpp"

SisAuth::SisAuth() {

	if (std::filesystem::exists("/usr/bin/argon2") == false) {
		std::cout << "Argon2 not found! SisAuth will not work.";
		hasArgon2 = false;
	}
	else {
		hasArgon2 = true;
	}

}


std::string SisAuth::generateHash(const std::string& _password, unsigned int _length) {

	if (hasArgon2 == false)
		return "";

	std::string command = "echo \"" + _password + "\" | argon2 saltItWithSalt -r -l " + std::to_string(_length);
	FILE *process = popen(command.c_str(), "r");
	if (process == nullptr)
		return "";

	std::string hash;
	char c;
	while ((c=fgetc(process)) != '\n')
		hash += c;

	pclose(process);

	return hash;
}

bool SisAuth::checkHash(const std::string& _password, const std::string& _hash, unsigned int _length) {

	std::string checkHash = generateHash(_password, _length);
	if (checkHash == _hash)
		return true;

	return false;
}


SisAuth::~SisAuth() {}
