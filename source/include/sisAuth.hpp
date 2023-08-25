
#ifndef SIS_AUTH_H_
#define SIS_AUTH_H_

#include <iostream>
#include <filesystem>
#include <string>

class SisAuth {

public:

	SisAuth();

	std::string generateHash(const std::string& _password, unsigned int _length = 32);
	bool checkHash(const std::string& _password, const std::string& _hash, unsigned int _length = 32);

	~SisAuth();

private:
	bool hasArgon2;

};

#endif // !SIS_AUTH_H_
