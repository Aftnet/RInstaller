#pragma once

#include "certstore.h"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

struct mbedtls_net_context;
struct mbedtls_ssl_context;
struct mbedtls_ssl_config;

namespace RInstaller
{
	class MbedtlsMgr;

	class Client
	{
		enum class Result
		{
			Ok, Busy, Cancelled, AlreadyConnected, NotConnected, HostNotResolvable, HostNotConnectable, TlsNegotiationError, OtherError
		};

		enum class CertificateValidationAction
		{
			AcceptAlways, AcceptOnce, RejectAlways, RejectOnce
		};

	private:
		const std::function<CertificateValidationAction(const std::string&)> CertValidationCB;
		std::atomic_bool Busy, CancelRequested;
		MbedtlsMgr& TlsMgr;
		CertificateStore CertStore;
		std::unique_ptr<mbedtls_net_context, void(*)(mbedtls_net_context*)> Socket;
		std::unique_ptr<mbedtls_ssl_context, void(*)(mbedtls_ssl_context*)> SslContext;
		std::unique_ptr<mbedtls_ssl_config, void(*)(mbedtls_ssl_config*)> SslConfig;
		std::chrono::steady_clock::time_point TimeoutBase;


	public:
		Client(const std::filesystem::path&, std::function<CertificateValidationAction(const std::string&)>&);
		Result Connect(const std::string&, const std::chrono::milliseconds&);
		Result Disconnect();
		Result PushFile();
		Result Install();
		Result Cancel();

		void ProgressCB(int);
	};
}
