#pragma once

#include <string>
#include <vector>

class CertStore
{
public:
	CertStore() {};
	~CertStore() {};

	void Init();
private:
	std::string GetSha1Thumbprint(const std::vector<unsigned char>& data);
};
