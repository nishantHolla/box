
#include "box.hpp"
#include <chrono>
#include <thread>

int main (int argc, char *argv[]) {
	Box box ("./testSite");

	// box.wrap();
	// box.unwrap();
	// box.create();
	box.index();

	return 0;
}
