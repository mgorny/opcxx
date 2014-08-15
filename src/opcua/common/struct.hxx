/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_STRUCT_HXX
#define OPCUA_COMMON_STRUCT_HXX 1

#include <opcua/common/types.hxx>
#include <opcua/common/util.hxx>

namespace opc_ua
{
	struct RequestHeader : Struct
	{
		NodeId authentication_token;
		DateTime timestamp;
		UInt32 request_handle;
		UInt32 return_diagnostics;
		String audit_entry_id;
		UInt32 timeout_hint;
		// XXX: this should be ExtensionObject
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

};

#endif /*OPCUA_COMMON_STRUCT_HXX*/
