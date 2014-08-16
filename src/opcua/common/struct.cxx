/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "struct.hxx"

template <class T>
constexpr opc_ua::Message* message_constructor()
{
	return new T;
}

template <class T>
constexpr opc_ua::MessageConstructorMap::value_type M()
{
	return {T::NODE_ID, message_constructor<T>};
}

const opc_ua::MessageConstructorMap opc_ua::message_constructors{
	M<OpenSecureChannelRequest>(),
	M<OpenSecureChannelResponse>(),
	M<CloseSecureChannelRequest>(),
	M<CloseSecureChannelResponse>(),
};

opc_ua::RequestHeader::RequestHeader()
{
}

opc_ua::RequestHeader::RequestHeader(UInt32 req_handle)
	: authentication_token(0),
	timestamp(DateTime::now()),
	request_handle(req_handle),
	return_diagnostics(0),
	audit_entry_id(""),
	timeout_hint(0),
	additional_header()
{
}

void opc_ua::RequestHeader::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, authentication_token);
	s.serialize(ctx, timestamp);
	s.serialize(ctx, request_handle);
	s.serialize(ctx, return_diagnostics);
	s.serialize(ctx, audit_entry_id);
	s.serialize(ctx, timeout_hint);
	s.serialize(ctx, additional_header);
}

void opc_ua::RequestHeader::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, authentication_token);
	s.unserialize(ctx, timestamp);
	s.unserialize(ctx, request_handle);
	s.unserialize(ctx, return_diagnostics);
	s.unserialize(ctx, audit_entry_id);
	s.unserialize(ctx, timeout_hint);
	s.unserialize(ctx, additional_header);
}

opc_ua::DiagnosticInfo::DiagnosticInfo()
{
}

void opc_ua::DiagnosticInfo::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, flags);
}

void opc_ua::DiagnosticInfo::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, flags);
}

opc_ua::ResponseHeader::ResponseHeader()
{
}

void opc_ua::ResponseHeader::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, timestamp);
	s.serialize(ctx, request_handle);
	s.serialize(ctx, service_result);
	s.serialize(ctx, service_diagnostics);
	s.serialize(ctx, string_table);
	s.serialize(ctx, additional_header);
}

void opc_ua::ResponseHeader::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, timestamp);
	s.unserialize(ctx, request_handle);
	s.unserialize(ctx, service_result);
	s.unserialize(ctx, service_diagnostics);
	s.unserialize(ctx, string_table);
	s.unserialize(ctx, additional_header);
}

opc_ua::OpenSecureChannelRequest::OpenSecureChannelRequest()
{
}

opc_ua::OpenSecureChannelRequest::OpenSecureChannelRequest(UInt32 req_handle, SecurityTokenRequestType req_type, MessageSecurityMode req_mode, ByteString req_nonce, UInt32 req_lifetime)
	: request_header(req_handle),
	request_type(req_type),
	security_mode(req_mode),
	client_nonce(req_nonce),
	requested_lifetime(req_lifetime)
{
}

void opc_ua::OpenSecureChannelRequest::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, client_protocol_version);
	s.serialize(ctx, static_cast<UInt32>(request_type));
	s.serialize(ctx, static_cast<UInt32>(security_mode));
	s.serialize(ctx, client_nonce);
	s.serialize(ctx, requested_lifetime);
}

void opc_ua::OpenSecureChannelRequest::unserialize(SerializationContext& ctx, Serializer& s)
{
	UInt32 n_request_type, n_security_mode;

	s.unserialize(ctx, request_header);
	s.unserialize(ctx, client_protocol_version);
	s.unserialize(ctx, n_request_type);
	s.unserialize(ctx, n_security_mode);
	s.unserialize(ctx, client_nonce);
	s.unserialize(ctx, requested_lifetime);

	request_type = static_cast<SecurityTokenRequestType>(n_request_type);
	security_mode = static_cast<MessageSecurityMode>(n_security_mode);
}

opc_ua::ChannelSecurityToken::ChannelSecurityToken()
{
}

void opc_ua::ChannelSecurityToken::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, channel_id);
	s.serialize(ctx, token_id);
	s.serialize(ctx, created_at);
	s.serialize(ctx, revised_lifetime);
}

void opc_ua::ChannelSecurityToken::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, channel_id);
	s.unserialize(ctx, token_id);
	s.unserialize(ctx, created_at);
	s.unserialize(ctx, revised_lifetime);
}

opc_ua::OpenSecureChannelResponse::OpenSecureChannelResponse()
{
}

void opc_ua::OpenSecureChannelResponse::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
	s.serialize(ctx, server_protocol_version);
	s.serialize(ctx, security_token);
	s.serialize(ctx, server_nonce);
}

void opc_ua::OpenSecureChannelResponse::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
	s.unserialize(ctx, server_protocol_version);
	s.unserialize(ctx, security_token);
	s.unserialize(ctx, server_nonce);
}

opc_ua::CloseSecureChannelRequest::CloseSecureChannelRequest()
{
}

opc_ua::CloseSecureChannelRequest::CloseSecureChannelRequest(UInt32 req_handle)
	: request_header(req_handle)
{
}

void opc_ua::CloseSecureChannelRequest::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
}

void opc_ua::CloseSecureChannelRequest::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, request_header);
}

opc_ua::CloseSecureChannelResponse::CloseSecureChannelResponse()
{
}

void opc_ua::CloseSecureChannelResponse::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
}

void opc_ua::CloseSecureChannelResponse::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
}
