
#include "box.hpp"
#include <iostream>


Box::Informer::Informer(SisIO *_io) :
	io (_io),
	inJob (false)
{}

void Box::Informer::beginJob(const std::string& _sectionName, const int _targetCount) {
	if (inJob)
		return;

	isUntargeted = (_targetCount < 0);

	inJob = true;
	sectionName = _sectionName;
	currentCount = 0;
	targetCount = _targetCount;
	io->output(SisIO::messageType::info, "Started job: " + _sectionName);
}

void Box::Informer::progressJob(const std::string& _message) {
	if (currentCount != 0)
		std::cout << ANSI_MOVE_UP << ANSI_CLEAR_LINE;

	currentCount++;
	std::string progressMeter = "";
	if (isUntargeted == false)
		progressMeter = std::to_string(currentCount) + "/" + std::to_string(targetCount);

	io->output(SisIO::messageType::info, progressMeter + " " + _message);
}

void Box::Informer::endJob() {
	inJob = false;
	std::cout << ANSI_MOVE_UP << ANSI_CLEAR_LINE;
	io->output(SisIO::messageType::okay, "Finished job: " + sectionName);
}

Box::Informer::~Informer()
{}
