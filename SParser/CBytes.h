#pragma once
class CBytes
{
public:
	static void Invert(unsigned char *ptr, unsigned int length)
	{
		for (int i = 0, _len = length / 2; i < _len; i++)
		{
			unsigned char j = *(ptr + i);
			*(ptr + i) = *(ptr + length - 1 - i);
			*(ptr + length - 1 - i) = j;
		}
	}

	unsigned int length;
	unsigned char *bytes;

	CBytes() {
		bytes = nullptr;
		length = 0;
	}
	~CBytes() {
		if (length > 0 && bytes != nullptr)
			delete[] bytes;
	}
};
