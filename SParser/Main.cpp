#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <WinSock2.h>
#include <ctime>

#include "CHandshake.h"
#include "CClientHello.h"

#pragma comment(lib, "Wsock32.lib")

#define LENGTH_BUFF 512

SOCKET s;
unsigned char buffRECV[LENGTH_BUFF] = {};
int actual_len;

enum STATE_RECV
{
	WAIT_START_MSG,
	RECV_ALL_LENGTH,
	SERVER_HELLO_DONE
};

STATE_RECV state = WAIT_START_MSG;

unsigned char HandshakeType = UCHAR_MAX;
unsigned int LengthHandshakeProtocol = UINT_MAX;
int gIndex = 0;

void GetNewRecv()
{
	if (SOCKET_ERROR == (actual_len = recv(s, (char*)&buffRECV, LENGTH_BUFF, 0)))
	{
		closesocket(s);
		printf("Error: %i", WSAGetLastError());
		getchar();

		exit(0);
	}
}

void GetPacket(unsigned char **ptr)
{
	if (*ptr == nullptr)
		*ptr = new unsigned char[LengthHandshakeProtocol]();

	unsigned char *packet = *ptr;

	for (int i = 0; i < LengthHandshakeProtocol; i++)
	{
		if (gIndex == actual_len)
		{
			GetNewRecv();
			gIndex = 0;
		}
		else if (gIndex > actual_len) throw;

		packet[i] = *(buffRECV + gIndex);

		if (gIndex == actual_len)
		{
			GetNewRecv();
			gIndex = 0;
		}
		else if (gIndex > actual_len) throw;
		else gIndex++;
	}

	HandshakeType = UCHAR_MAX;
	LengthHandshakeProtocol = UINT_MAX;
	state = WAIT_START_MSG;
}

void Invert(unsigned char *ptr, unsigned int length)
{
	for (int i = 0, _len = length / 2; i < _len; i++)
	{
		unsigned char j = *(ptr + i);
		*(ptr + i) = *(ptr + length - 1 - i);
		*(ptr + length - 1 - i) = j;
	}
}

int main()
{
	srand(time(nullptr));

	CClientHello cHello = CClientHello(CClientHello::TLS1_2);
	cHello.cipher_suites.push_back(CClientHello::ReservedGREASE);
	cHello.cipher_suites.push_back(CClientHello::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
	cHello.CreateBytes();

	CHandshake hHello = CHandshake(CHandshake::TLS1_2, &cHello);
	CBytes * helloMy = hHello.CreateBytes();

	WSADATA ws;

	if (FAILED(WSAStartup(MAKEWORD(1, 1), &ws)))
	{
		printf("Error: %i", WSAGetLastError());
		getchar();

		return 0;
	}

	if (INVALID_SOCKET == (s = socket(AF_INET, SOCK_STREAM, 0)))
	{
		printf("Error: %i", WSAGetLastError());
		getchar();

		return 0;
	}

	sockaddr_in addr;
	ZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1"); 
	addr.sin_port = htons(443);

	if (SOCKET_ERROR == (connect(s, (sockaddr *)&addr, sizeof(addr))))
	{
		closesocket(s);
		printf("Error: %i", WSAGetLastError());
		getchar();

		return 0;
	}

	if (SOCKET_ERROR == (send(s, (char*)(*helloMy).bytes, (*helloMy).length, 0)))
	{
		closesocket(s);
		printf("Error: %i", WSAGetLastError());
		getchar();

		return 0;
	}

	unsigned char *serverHello = nullptr; size_t serverHelloLength = 0;
	unsigned char *certificate = nullptr; size_t certificateLength = 0;
	unsigned char *certificateStatus = nullptr; size_t certificateStatusLength = 0;
	unsigned char *serverKeyExchange = nullptr; size_t serverKeyExchangeLength = 0;

	GetNewRecv();

	unsigned char StartMsg[3] = { 0x16, 0x03, 0x03 };
	
	for (int i = 0; i < 3; i++)
		StartMsg[i] = buffRECV[i];

	if (StartMsg[1] != 0x03 || StartMsg[2] != 0x03) throw;

	while (state != SERVER_HELLO_DONE)
	{
		while (state == WAIT_START_MSG)
		{
			bool finded = true;

			for (; gIndex < actual_len - 2; gIndex++)
			{
				finded = true;

				for (int j = 0; j < 3; j++)
				{
					if (*(buffRECV + gIndex + j) != StartMsg[j])
					{
						finded = false;
						break;
					}
				}

				if (finded)
				{
					state = RECV_ALL_LENGTH;
					gIndex += 3 + 2;
					break;
				}
			}

			if (actual_len - gIndex == 2 && !finded)
			{
				unsigned char *tmp = new unsigned char[3];

				memcpy(tmp, buffRECV + gIndex, 2);
				GetNewRecv();
				gIndex = 0;

				for (int k = 0; k < 2; k++)
				{ 
					tmp[2] = buffRECV[k];

					finded = true;

					for (int j = 0; j < 3; j++)
					{
						if (tmp[j] != StartMsg[j])
						{
							finded = false;
							break;
						}
					}

					if (finded)
					{
						state = RECV_ALL_LENGTH;

						gIndex = 3 + k;

						break;
					}

					for (int j = 1; j < 3; j++)
						tmp[j - 1] = tmp[j];
				}

				delete[] tmp;
			}
		}

		if (state == RECV_ALL_LENGTH)
		{
			if (gIndex == actual_len)
			{
				gIndex = 0;
				GetNewRecv();
			}
			else if (gIndex > actual_len) throw;

			if (HandshakeType == UCHAR_MAX)
			{
				HandshakeType = *(buffRECV + gIndex);
				gIndex += sizeof(HandshakeType);
			}
			
			if (gIndex == actual_len)
			{
				gIndex = 0;
				GetNewRecv();
			}
			else if (gIndex > actual_len) throw;

			if (LengthHandshakeProtocol == UINT_MAX)
			{
				LengthHandshakeProtocol = 0;
				for (int i = 1; i < 4; i++)
				{
					*((unsigned char *)&LengthHandshakeProtocol + 3 - i) = *(buffRECV + gIndex);

					if (gIndex == actual_len)
					{
						GetNewRecv();
						gIndex = 0;
					}
					else if (gIndex > actual_len) throw;
					else gIndex++;
				}
			}

			if (gIndex == actual_len && HandshakeType != 0x0e)
			{
				GetNewRecv();
				gIndex = 0;
			}
			else if (gIndex > actual_len) throw;

			switch (HandshakeType)
			{
			case 0x02:{
				serverHelloLength = LengthHandshakeProtocol;
				GetPacket(&serverHello);

				break; 
			}
			case 0x0b: {
				certificateLength = LengthHandshakeProtocol;
				GetPacket(&certificate);

				break; 
			}
			case 0x16: {
				certificateStatusLength = LengthHandshakeProtocol;
				GetPacket(&certificateStatus);

				break; 
			}
			case 0x0c: {
				serverKeyExchangeLength = LengthHandshakeProtocol;
				GetPacket(&serverKeyExchange);

				break; 
			}
			case 0x0e: {
				HandshakeType = UCHAR_MAX;
				LengthHandshakeProtocol = UINT_MAX;
				state = SERVER_HELLO_DONE;

				break; 
			}
			default:
				break;
			}
		}
	}

	if (serverHello != nullptr)
	{
		printf("Server Hello\n");
		for (int i = 0; i < serverHelloLength; i++)
			printf("%0*x ", 2, serverHello[i]);
		printf("\n\n");
	}

	if (certificate != nullptr)
	{
		printf("Certificate\n");
		for (int i = 0; i < certificateLength; i++)
			printf("%0*x ", 2, certificate[i]);
		printf("\n\n");
	}

	if (certificateStatus != nullptr)
	{
		printf("Certificate Status\n");
		for (int i = 0; i < certificateStatusLength; i++)
			printf("%0*x ", 2, certificateStatus[i]);
		printf("\n\n");
	}

	if (serverKeyExchange != nullptr)
	{
		printf("Server Key Exchange\n");
		for (int i = 0; i < serverKeyExchangeLength; i++)
			printf("%0*x ", 2, serverKeyExchange[i]);
		printf("\n\n");
	}

	

	delete[] serverHello;
	delete[] certificate;
	delete[] certificateStatus;
	delete[] serverKeyExchange;

	closesocket(s);

	getchar();
	return 0;
}