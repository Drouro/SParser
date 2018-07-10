#pragma once
#include "CBytes.h"
#include <cstring>

class CHandshake
{
public:
	enum Version
	{
		TLS1_2 = 0x0303
	};

	CBytes *CreateBytes();

	CHandshake();
	CHandshake(CHandshake::Version version, CBytes *bytes);
	~CHandshake();
private:
	CBytes * bytesMain;
	Version ver;
	
};