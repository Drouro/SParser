#include "CClientHello.h"

CClientHello::CClientHello()
{

}

CClientHello::CClientHello(CClientHello::Version version)
{
	session_id_length = 0;
	ver = version;
}

void CClientHello::CreateBytes()
{
	unsigned int size_extensions = 0;

	bytes = new unsigned char[1 + 3 + 2 + 32 + 1 + session_id_length + 2 + 2 * cipher_suites.size() + 1 + 1 + 2 + size_extensions]();
	length = 1 + 3 + 2 + 32 + 1 + session_id_length + 2 + 2 * cipher_suites.size() + 1 + 1 + 2 + size_extensions;

	*(bytes + 0) = 0x01;
	
	// Length
	int t0 = 2 + 32 + 1 + session_id_length + 2 + 2 * cipher_suites.size() + 1 + 1 + 2 + size_extensions;
	for (int i = 0; i < 3; i++)
		bytes[1 + i] = *((unsigned char*)&t0 + 2 - i);
	
	// Version
	*((unsigned __int16*)(bytes + 4)) = ver;
	Invert(bytes + 4, 2);

	// Random
	*((unsigned int*)(bytes + 6)) = std::time(nullptr);
	Invert(bytes + 6, 4);

	for (int i = 0; i < 28; i++) bytes[6 + 4 + i] = rand() % UCHAR_MAX;

	// Session ID
	*(bytes + 1 + 3 + 2 + 32) = session_id_length;
	if (session_id_length > 0)
		memcpy(bytes + 1 + 3 + 2 + 32 + 1, session_id, session_id_length);

	// Cipher Suites
	*((unsigned __int16*)(bytes + 6 + 32 + 1 + session_id_length)) = 2 * cipher_suites.size();
	Invert(bytes + 6 + 32 + 1 + session_id_length, 2);

	for (int i = 0; i < cipher_suites.size(); i++)
	{
		*((unsigned __int16*)(bytes + 6 + 32 + 1 + session_id_length + 2 + 2 * i)) = cipher_suites[i];
		Invert(bytes + 6 + 32 + 1 + session_id_length + 2 + 2 * i, 2);
	}

	// Compression Methods
	*(bytes + 1 + 3 + 2 + 32 + 1 + session_id_length + 2 + 2 * cipher_suites.size()) = 1;
	*(bytes + 1 + 3 + 2 + 32 + 1 + session_id_length + 2 + 2 * cipher_suites.size() + 1) = 0x0;

	// Extensions
	*((unsigned __int16*)(bytes + 1 + 3 + 2 + 32 + 1 + session_id_length + 2 + 2 * cipher_suites.size() + 1 + 1)) = size_extensions;
}


CClientHello::~CClientHello()
{
}
