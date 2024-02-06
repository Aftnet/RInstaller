#pragma once

#include "certstore.h"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

struct mbedtls_net_context;

namespace RInstaller
{
	class MbedtlsMgr;

	class Client
	{
		enum class Result
		{
			Ok, Busy, AlreadyConnected, NotConnected, HostNotResolvable, HostNotConnectable, TlsNegotiationError, OtherError
		};

	private:
		std::atomic_bool Busy, CancelRequested;
		MbedtlsMgr& TlsMgr;
		CertificateStore CertStore;
		std::unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> Socket;
		std::chrono::steady_clock::time_point TimeoutBase;

	public:
		Client(const std::filesystem::path&);
		Result Connect(const std::string&, const std::chrono::milliseconds&);
		Result Disconnect();
		Result PushFile();
		Result Install();
		Result Cancel();

		void ProgressCB(int);
	};
}
