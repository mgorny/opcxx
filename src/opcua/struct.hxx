/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef STRUCT_HXX
#define STRUCT_HXX 1

#include <opcua/types.hxx>
#include <opcua/util.hxx>

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

	struct OpenSecureChannelRequest : Struct
	{
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

	struct OpenSecureChannelResponse : Struct
	{
		ResponseHeader response_header;
		UInt32 server_protocol_version;
		ChannelSecurityToken security_token;
		ByteString server_nonce;

		// non-initializing constructor
		OpenSecureChannelResponse();
		// metadata
		virtual void serialize(SerializationContext& ctx, Serializer& s) const;
		virtual void unserialize(SerializationContext& ctx, Serializer& s);
	};

	typedef RequestHeader CloseSecureChannelRequest;
	typedef ResponseHeader CloseSecureChannelResponse;
};

#endif /*STRUCT_HXX*/
