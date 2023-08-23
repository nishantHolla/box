
#include "box.hpp"
#include <chrono>
#include <thread>

int main (int argc, char *argv[]) {
	Box box;

	box.informer.beginSection("Hello world", 10);
	for (int i=0; i<10; i++) {
		box.informer.progress(std::to_string(i));
		std::this_thread::sleep_for(std::chrono::seconds(2));
	}
	box.informer.endSection();
	return 0;
}
