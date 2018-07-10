#include "CHandshake.h"



CHandshake::CHandshake()
{

}



CHandshake::CHandshake(CHandshake::Version version, CBytes * bytes)
{
	ver = version;
	bytesMain = bytes;
}

CBytes *CHandshake::CreateBytes()
{
	CBytes *bytesHandshake = new CBytes();
	
	bytesHandshake->bytes = new unsigned char[5 + (*bytesMain).length];
	bytesHandshake->length = 5 + (*bytesMain).length;

	bytesHandshake->bytes[0] = 0x16;

	*((unsigned __int16*)(bytesHandshake->bytes + 1)) = ver;
	*((unsigned __int16*)(bytesHandshake->bytes + 3)) = (*bytesMain).length;

	CBytes::Invert(bytesHandshake->bytes + 1, 2);
	CBytes::Invert(bytesHandshake->bytes + 3, 2);

	memcpy(bytesHandshake->bytes + 5, (*bytesMain).bytes, (*bytesMain).length);

	return bytesHandshake;
}

CHandshake::~CHandshake()
{
}
