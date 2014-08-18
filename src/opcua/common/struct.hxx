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

		RequestHeader();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct Request : Message
	{
		RequestHeader request_header;
	};

	// opaque 32-bit status code
	typedef UInt32 StatusCode;

	struct DiagnosticInfo : Struct
	{
		Byte flags;

		// TODO: optional fields

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

		ResponseHeader();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct Response : Message
	{
		ResponseHeader response_header;
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

	struct OpenSecureChannelRequest : Request
	{
		static constexpr UInt32 NODE_ID = 444;

		UInt32 client_protocol_version;
		SecurityTokenRequestType request_type;
		MessageSecurityMode security_mode;
		ByteString client_nonce;
		UInt32 requested_lifetime;

		OpenSecureChannelRequest(SecurityTokenRequestType req_type = SecurityTokenRequestType::ISSUE, MessageSecurityMode req_mode = MessageSecurityMode::NONE, ByteString req_nonce = "", UInt32 req_lifetime = 0);

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

		ChannelSecurityToken();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct OpenSecureChannelResponse : Response
	{
		static constexpr UInt32 NODE_ID = 447;

		UInt32 server_protocol_version;
		ChannelSecurityToken security_token;
		ByteString server_nonce;

		OpenSecureChannelResponse();
		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct CloseSecureChannelRequest : Request
	{
		static constexpr UInt32 NODE_ID = 450;

		CloseSecureChannelRequest();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct CloseSecureChannelResponse : Response
	{
		static constexpr UInt32 NODE_ID = 453;

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

		ApplicationDescription(ApplicationType app_type = ApplicationType::SERVER);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct CreateSessionRequest : Request
	{
		static constexpr UInt32 NODE_ID = 459;

		ApplicationDescription client_description;
		String server_uri;
		String endpoint_uri;
		String session_name;
		ByteString client_nonce;
		ByteString client_certificate;
		Double requested_session_timeout;
		UInt32 max_response_message_size;

		CreateSessionRequest(ApplicationType app_type = ApplicationType::SERVER, String endpoint = "", String session = "", String nonce = "", Double session_timeout = 0);

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

		EndpointDescription();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct SignedSoftwareCertificate : Struct
	{
		ByteString certificate_data;
		ByteString signature;

		SignedSoftwareCertificate();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct SignatureData : Struct
	{
		String algorithm;
		ByteString signature;

		SignatureData();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	struct CreateSessionResponse : Response
	{
		static constexpr UInt32 NODE_ID = 462;

		NodeId session_id;
		NodeId authentication_token;
		Double revised_session_timeout;
		ByteString server_nonce;
		ByteString server_certificate;
		Array<EndpointDescription> server_endpoints;
		Array<SignedSoftwareCertificate> server_software_certificates;
		SignatureData server_signature;
		UInt32 max_request_message_size;

		CreateSessionResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct ActivateSessionRequest : Request
	{
		static constexpr UInt32 NODE_ID = 465;

		SignatureData client_signature;
		Array<SignedSoftwareCertificate> client_software_certificates;
		Array<String> locale_ids;
		ExtensionObject user_identity_token;
		SignatureData user_token_signature;

		ActivateSessionRequest();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct ActivateSessionResponse : Response
	{
		static constexpr UInt32 NODE_ID = 468;

		ByteString server_nonce;
		Array<StatusCode> results;
		Array<DiagnosticInfo> diagnostic_infos;

		ActivateSessionResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct CloseSessionRequest : Request
	{
		static constexpr UInt32 NODE_ID = 471;

		Boolean delete_subscriptions;

		CloseSessionRequest(Boolean del_subscriptions = false);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};

	struct CloseSessionResponse : Response
	{
		static constexpr UInt32 NODE_ID = 474;

		CloseSessionResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 node_id() const { return NODE_ID; }
	};
};

#endif /*OPCUA_COMMON_STRUCT_HXX*/
