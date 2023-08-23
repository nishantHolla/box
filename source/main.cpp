
#include "box.hpp"
#include <chrono>
#include <thread>

int main (int argc, char *argv[]) {
	Box box ("./testSite");
	box.flipAllFiles();
	return 0;
}
