#pragma once
#include "CBytes.h"
#include <vector>
#include <ctime>

class CClientHello : public CBytes
{
public:
	enum Version
	{
		TLS1_2 = 0x0303
	};

	enum CipherSuite
	{
		ReservedGREASE = 0x2a2a,
		TLS_AES_128_GCM_SHA256 = 0x1301,
		TLS_AES_256_GCM_SHA384 = 0x1302,
		TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
		TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
		TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
		TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
		TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
	};

	unsigned __int8 session_id_length;
	unsigned char *session_id;

	std::vector<CipherSuite> cipher_suites = std::vector<CipherSuite>();
	std::vector<unsigned char *> extensions = std::vector<unsigned char *>();;

	void CreateBytes();

	CClientHello();
	CClientHello(CClientHello::Version version);
	~CClientHello();
private:
	Version ver;
};

