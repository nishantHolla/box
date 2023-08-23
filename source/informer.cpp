
#include "box.hpp"
#include <iostream>


Box::Informer::Informer(SisIO *_io) :
	io (_io),
	inSection (false)
{}

void Box::Informer::beginSection(const std::string& _sectionName, const int _targetCount) {
	if (inSection)
		return;

	inSection = true;
	currentCount = 0;
	targetCount = _targetCount;
	io->output(SisIO::messageType::info, _sectionName);
}

void Box::Informer::progress(const std::string& _message) {
	if (currentCount != 0)
		std::cout << ANSI_MOVE_UP << ANSI_CLEAR_LINE;

	currentCount++;
	std::string progressMeter = std::to_string(currentCount) + "/" + std::to_string(targetCount);
	io->output(SisIO::messageType::info, progressMeter + " " + _message);
}

void Box::Informer::endSection() {
	inSection = false;
	for (int i=0; i<3; i++)
		std::cout << ANSI_CLEAR_LINE << ANSI_MOVE_UP;
}

Box::Informer::~Informer()
{}
