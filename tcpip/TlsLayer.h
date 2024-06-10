#pragma once
#include "Vrecv.h"

class TlsLayer : public Vrecv
{
public:
	TlsLayer(int port);

protected:
	int get_full_length(const std::string& s);
};