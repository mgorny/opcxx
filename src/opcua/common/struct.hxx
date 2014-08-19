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
		static constexpr UInt32 NODE_ID = 389;

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
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct Request : Message
	{
		RequestHeader request_header;
	};

	// opaque 32-bit status code
	typedef UInt32 StatusCode;

	struct DiagnosticInfo : Struct
	{
		static constexpr UInt32 NODE_ID = 25;

		Byte flags;

		// TODO: optional fields

		DiagnosticInfo();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct ResponseHeader : Struct
	{
		static constexpr UInt32 NODE_ID = 392;

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
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct ChannelSecurityToken : Struct
	{
		static constexpr UInt32 NODE_ID = 441;

		UInt32 channel_id;
		UInt32 token_id;
		DateTime created_at;
		UInt32 revised_lifetime;

		ChannelSecurityToken();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct CloseSecureChannelRequest : Request
	{
		static constexpr UInt32 NODE_ID = 450;

		CloseSecureChannelRequest();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct CloseSecureChannelResponse : Response
	{
		static constexpr UInt32 NODE_ID = 453;

		CloseSecureChannelResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		static constexpr UInt32 NODE_ID = 308;

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
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		static constexpr UInt32 NODE_ID = 304;

		String policy_id;
		UserTokenType token_type;
		String issued_token_type;
		String issuer_endpoint_url;
		String security_policy_uri;

		UserTokenPolicy();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct EndpointDescription : Struct
	{
		static constexpr UInt32 NODE_ID = 312;

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
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct SignedSoftwareCertificate : Struct
	{
		static constexpr UInt32 NODE_ID = 344;

		ByteString certificate_data;
		ByteString signature;

		SignedSoftwareCertificate();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct SignatureData : Struct
	{
		static constexpr UInt32 NODE_ID = 456;

		String algorithm;
		ByteString signature;

		SignatureData();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		virtual UInt32 get_node_id() const { return NODE_ID; }
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
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct CloseSessionRequest : Request
	{
		static constexpr UInt32 NODE_ID = 471;

		Boolean delete_subscriptions;

		CloseSessionRequest(Boolean del_subscriptions = false);

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct CloseSessionResponse : Response
	{
		static constexpr UInt32 NODE_ID = 474;

		CloseSessionResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct QualifiedName : Struct
	{
		static constexpr UInt32 NODE_ID = 20;

		Int32 namespace_index;
		CharArray name;

		QualifiedName(Int32 ns_index = 0, CharArray new_name = "");

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct RelativePathElement : Struct
	{
		static constexpr UInt32 NODE_ID = 537;

		NodeId reference_type_id;
		Boolean is_inverse;
		Boolean include_subtypes;
		QualifiedName target_name;

		RelativePathElement(NodeId ref_type = 0, Boolean is_inv = false, Boolean inc_subtypes = false, QualifiedName target = {});

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct RelativePath : Struct
	{
		static constexpr UInt32 NODE_ID = 540;

		Array<RelativePathElement> elements;

		RelativePath(Array<RelativePathElement> new_elements = {});

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct BrowsePath : Struct
	{
		static constexpr UInt32 NODE_ID = 543;

		NodeId starting_node;
		RelativePath relative_path;

		BrowsePath(NodeId start = 0, RelativePath path = {});

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct TranslateBrowsePathsToNodeIdsRequest : Request
	{
		static constexpr UInt32 NODE_ID = 552;

		Array<BrowsePath> browse_paths;

		TranslateBrowsePathsToNodeIdsRequest(Array<BrowsePath> paths = {});

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	enum class TimestampsToReturn
	{
		SOURCE = 0,
		SERVER = 1,
		BOTH = 2,
		NEITHER = 3,
	};

	struct ReadValueId : Struct
	{
		static constexpr UInt32 NODE_ID = 626;

		NodeId node_id;
		UInt32 attribute_id;
		String index_range;
		QualifiedName data_encoding;

		ReadValueId();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct ReadRequest : Request
	{
		static constexpr UInt32 NODE_ID = 629;

		Double max_age;
		TimestampsToReturn timestamps_to_return;
		Array<ReadValueId> nodes_to_read;

		ReadRequest();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct DataValue : Struct
	{
		static constexpr UInt32 NODE_ID = 23;

		Byte flags;
		Variant value;
		StatusCode status_code;
		DateTime source_timestamp;
		UInt16 source_picoseconds;
		DateTime server_timestamp;
		UInt16 server_picoseconds;

		DataValue();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct ReadResponse : Response
	{
		static constexpr UInt32 NODE_ID = 632;

		Array<DataValue> results;
		Array<DiagnosticInfo> diagnostic_infos;

		ReadResponse();

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct UserIdentityToken : Struct
	{
		static constexpr UInt32 NODE_ID = 316;

		String policy_id;

		UserIdentityToken(String new_policy_id = "");

		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
		virtual UInt32 get_node_id() const { return NODE_ID; }
	};

	struct AnonymousUserIdentityToken : UserIdentityToken
	{
		AnonymousUserIdentityToken();
	};
};

#endif /*OPCUA_COMMON_STRUCT_HXX*/
