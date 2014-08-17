/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_STRUCT_HXX
#define OPCUA_COMMON_STRUCT_HXX 1

#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>

#include <unordered_map>

namespace opc_ua
{
	// std::function<> triggers undefined symbols for NODE_ID
	typedef Message* (*MessageConstructorType)();
	typedef std::unordered_map<UInt32, MessageConstructorType> MessageConstructorMap;
	extern const MessageConstructorMap message_constructors;

	struct RequestHeader : Struct
	{
		NodeId authentication_token;
		DateTime timestamp;
		UInt32 request_handle;
		UInt32 return_diagnostics;
		String audit_entry_id;
		UInt32 timeout_hint;
		ExtensionObject additional_header;

		// non-initializing constructor
		RequestHeader();
		// initializing constructor
		RequestHeader(UInt32 req_handle);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	// opaque 32-bit status code
	typedef UInt32 StatusCode;

	struct DiagnosticInfo : Struct
	{
		Byte flags;

		// TODO: optional fields

		// non-initializing constructor
		DiagnosticInfo();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct ResponseHeader : Struct
	{
		DateTime timestamp;
		UInt32 request_handle;
		StatusCode service_result;
		DiagnosticInfo service_diagnostics;
		Array<String> string_table;
		ExtensionObject additional_header;

		// non-initializing constructor
		ResponseHeader();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	enum class SecurityTokenRequestType
	{
		ISSUE = 0,
		RENEW = 1,
	};

	enum class MessageSecurityMode
	{
		INVALID = 0,
		NONE = 1,
		SIGN = 2,
		SIGN_AND_ENCRYPT = 3,
	};

	struct OpenSecureChannelRequest : Message
	{
		static constexpr UInt32 NODE_ID = 444;

		RequestHeader request_header;
		UInt32 client_protocol_version;
		SecurityTokenRequestType request_type;
		MessageSecurityMode security_mode;
		ByteString client_nonce;
		UInt32 requested_lifetime;

		// non-initializing constructor
		OpenSecureChannelRequest();
		// initializing constructor
		OpenSecureChannelRequest(UInt32 req_handle, SecurityTokenRequestType req_type, MessageSecurityMode req_mode, ByteString req_nonce, UInt32 req_lifetime);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct ChannelSecurityToken : Struct
	{
		UInt32 channel_id;
		UInt32 token_id;
		DateTime created_at;
		UInt32 revised_lifetime;

		// non-initializing constructor
		ChannelSecurityToken();
		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct OpenSecureChannelResponse : Message
	{
		static constexpr UInt32 NODE_ID = 447;

		ResponseHeader response_header;
		UInt32 server_protocol_version;
		ChannelSecurityToken security_token;
		ByteString server_nonce;

		// non-initializing constructor
		OpenSecureChannelResponse();
		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct CloseSecureChannelRequest : Message
	{
		static constexpr UInt32 NODE_ID = 450;

		RequestHeader request_header;

		// non-initializing constructor
		CloseSecureChannelRequest();
		// initializing constructor
		CloseSecureChannelRequest(UInt32 req_handle);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct CloseSecureChannelResponse : Message
	{
		static constexpr UInt32 NODE_ID = 453;

		ResponseHeader response_header;

		// non-initializing constructor
		CloseSecureChannelResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	enum class ApplicationType
	{
		SERVER = 0,
		CLIENT = 1,
		CLIENT_AND_SERVER = 2,
		DISCOVERY_SERVER = 3,
	};

	struct ApplicationDescription : Struct
	{
		String application_uri;
		String product_uri;
		LocalizedText application_name;
		ApplicationType application_type;
		String gateway_server_uri;
		String discovery_profile_uri;
		Array<String> discovery_urls;

		// non-initializing constructor
		ApplicationDescription();
		// initializing constructor
		ApplicationDescription(ApplicationType app_type);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct CreateSessionRequest : Message
	{
		static constexpr UInt32 NODE_ID = 459;

		RequestHeader request_header;
		ApplicationDescription client_description;
		String server_uri;
		String endpoint_uri;
		String session_name;
		ByteString client_nonce;
		ByteString client_certificate;
		Double requested_session_timeout;
		UInt32 max_response_message_size;

		// non-initializing constructor
		CreateSessionRequest();
		// initializing constructor
		CreateSessionRequest(UInt32 req_handle, ApplicationType app_type, String endpoint, String session, String nonce, Double session_timeout);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	enum class UserTokenType
	{
		ANONYMOUS = 0,
		USER_NAME = 1,
		CERTIFICATE = 2,
		ISSUED_TOKEN = 3,
	};

	struct UserTokenPolicy : Struct
	{
		String policy_id;
		UserTokenType token_type;
		String issued_token_type;
		String issuer_endpoint_url;
		String security_policy_uri;

		// non-initializing constructor
		UserTokenPolicy();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct EndpointDescription : Struct
	{
		String endpoint_url;
		ApplicationDescription server;
		ByteString server_certificate;
		MessageSecurityMode security_mode;
		String security_policy_uri;
		Array<UserTokenPolicy> user_identity_tokens;
		String transport_profile_uri;
		Byte security_level;

		// non-initializing constructor
		EndpointDescription();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct SignedSoftwareCertificate : Struct
	{
		ByteString certificate_data;
		ByteString signature;

		// non-initializing constructor
		SignedSoftwareCertificate();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct SignatureData : Struct
	{
		String algorithm;
		ByteString signature;

		// non-initializing constructor
		SignatureData();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct CreateSessionResponse : Message
	{
		static constexpr UInt32 NODE_ID = 462;

		ResponseHeader response_header;
		NodeId session_id;
		NodeId authentication_token;
		Double revised_session_timeout;
		ByteString server_nonce;
		ByteString server_certificate;
		Array<EndpointDescription> server_endpoints;
		Array<SignedSoftwareCertificate> server_software_certificates;
		SignatureData server_signature;
		UInt32 max_request_message_size;

		// non-initializing constructor
		CreateSessionResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};
};

#endif /*OPCUA_COMMON_STRUCT_HXX*/
