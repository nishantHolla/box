
#include "sisIO.hpp"

SisIO::SisIO(std::string _logFilePath) :
	logFilePath (_logFilePath),
	logLevel (messageType::none),
	outputLevel (messageType::none),
	colorMessages (true),
	tagMessages (true),
	colorReset ("\u001b[0m")
{

	messageTypeToColor[messageType::prompt] = messageColor::blue;
	messageTypeToColor[messageType::none] = messageColor::white;
	messageTypeToColor[messageType::okay] = messageColor::green;
	messageTypeToColor[messageType::info] = messageColor::cyan;
	messageTypeToColor[messageType::warn] = messageColor::yellow;
	messageTypeToColor[messageType::error] = messageColor::red;

	messageTypeToTag[messageType::prompt] = " [INPT] ";
	messageTypeToTag[messageType::none] = "  ";
	messageTypeToTag[messageType::okay] = " [OKAY] ";
	messageTypeToTag[messageType::info] = " [INFO] ";
	messageTypeToTag[messageType::warn] = " [WARN] ";
	messageTypeToTag[messageType::error] = " [ERRR] ";

	colorToAnsiCode[messageColor::blue] = "\u001b[34;1m";
	colorToAnsiCode[messageColor::white] = "\u001b[37;1m";
	colorToAnsiCode[messageColor::green] = "\u001b[32;1m";
	colorToAnsiCode[messageColor::cyan] = "\u001b[36;1m";
	colorToAnsiCode[messageColor::yellow] = "\u001b[33;1m";
	colorToAnsiCode[messageColor::red] = "\u001b[31;1m";

}

int SisIO::output(messageType _messageType, const std::string& _message, bool _endline) {

	if (_messageType < outputLevel)
		return 1;

	if (colorMessages)
		std::cout << colorToAnsiCode[messageTypeToColor[_messageType]];

	if (tagMessages)
		std::cout << messageTypeToTag[_messageType];

	std::cout << _message;

	if (colorMessages)
		std::cout << colorReset;

	if (_endline)
		std::cout << std::endl;

	std::cout << std::flush;
	return 0;
}

std::string SisIO::inputLine(const std::string& _message) {
	output(messageType::prompt, _message, false);
	std::cin >> std::ws;
	std::string result;
	std::getline(std::cin, result);
	return result;
}


int SisIO::log(messageType _messageType, const std::string& _message, const std::string _sender) {

	if (_messageType < logLevel)
		return 1;

	std::fstream logFile (logFilePath, std::ios::app);
	if (logFile.good() == false)
		return 2;

	logFile <<
		"\nFrom: " << _sender <<
		"\nType: " << messageTypeToTag[_messageType] <<
		"\nMessage: " << _message << "\n";

	logFile.close();
	return 0;
}

SisIO::~SisIO() {};
