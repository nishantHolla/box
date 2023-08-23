
#include "box.hpp"

Box::Box() :
	io (LOG_FILE)
{
	std::filesystem::remove(LOG_FILE);

}

Box::~Box()
{}
