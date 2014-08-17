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
	M<CreateSessionRequest>(),
	M<CreateSessionResponse>(),
	M<CloseSessionRequest>(),
	M<CloseSessionResponse>(),
};

opc_ua::RequestHeader::RequestHeader()
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
	s.serialize(ctx, ArraySerialization<String>(string_table));
	s.serialize(ctx, additional_header);
}

void opc_ua::ResponseHeader::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, timestamp);
	s.unserialize(ctx, request_handle);
	s.unserialize(ctx, service_result);
	s.unserialize(ctx, service_diagnostics);
	s.unserialize(ctx, ArrayUnserialization<String>(string_table));
	s.unserialize(ctx, additional_header);
}

opc_ua::OpenSecureChannelRequest::OpenSecureChannelRequest()
{
}

opc_ua::OpenSecureChannelRequest::OpenSecureChannelRequest(SecurityTokenRequestType req_type, MessageSecurityMode req_mode, ByteString req_nonce, UInt32 req_lifetime)
	: request_type(req_type),
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

opc_ua::ApplicationDescription::ApplicationDescription()
{
}

opc_ua::ApplicationDescription::ApplicationDescription(ApplicationType app_type)
	: application_uri(), product_uri(),
	application_name(), application_type(app_type),
	gateway_server_uri(), discovery_profile_uri(),
	discovery_urls()
{
}

void opc_ua::ApplicationDescription::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, application_uri);
	s.serialize(ctx, product_uri);
	s.serialize(ctx, application_name);
	s.serialize(ctx, static_cast<UInt32>(application_type));
	s.serialize(ctx, gateway_server_uri);
	s.serialize(ctx, discovery_profile_uri);
	s.serialize(ctx, ArraySerialization<String>(discovery_urls));
}

void opc_ua::ApplicationDescription::unserialize(SerializationContext& ctx, Serializer& s)
{
	UInt32 app_type;

	s.unserialize(ctx, application_uri);
	s.unserialize(ctx, product_uri);
	s.unserialize(ctx, application_name);
	s.unserialize(ctx, app_type);
	s.unserialize(ctx, gateway_server_uri);
	s.unserialize(ctx, discovery_profile_uri);
	s.unserialize(ctx, ArrayUnserialization<String>(discovery_urls));

	application_type = static_cast<ApplicationType>(app_type);
}

opc_ua::CreateSessionRequest::CreateSessionRequest()
{
}

opc_ua::CreateSessionRequest::CreateSessionRequest(ApplicationType app_type, String endpoint, String session, String nonce, Double session_timeout)
	: client_description(app_type),
	server_uri(),
	endpoint_uri(endpoint),
	session_name(session),
	client_nonce(nonce),
	client_certificate(),
	requested_session_timeout(session_timeout),
	max_response_message_size(0x1000000)
{
}

void opc_ua::CreateSessionRequest::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, client_description);
	s.serialize(ctx, server_uri);
	s.serialize(ctx, endpoint_uri);
	s.serialize(ctx, session_name);
	s.serialize(ctx, client_nonce);
	s.serialize(ctx, client_certificate);
	s.serialize(ctx, requested_session_timeout);
	s.serialize(ctx, max_response_message_size);
}

void opc_ua::CreateSessionRequest::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, request_header);
	s.unserialize(ctx, client_description);
	s.unserialize(ctx, server_uri);
	s.unserialize(ctx, endpoint_uri);
	s.unserialize(ctx, session_name);
	s.unserialize(ctx, client_nonce);
	s.unserialize(ctx, client_certificate);
	s.unserialize(ctx, requested_session_timeout);
	s.unserialize(ctx, max_response_message_size);
}

opc_ua::UserTokenPolicy::UserTokenPolicy()
	: policy_id(), token_type(), issued_token_type(),
	issuer_endpoint_url(), security_policy_uri()
{
}

void opc_ua::UserTokenPolicy::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, policy_id);
	s.serialize(ctx, static_cast<UInt32>(token_type));
	s.serialize(ctx, issued_token_type);
	s.serialize(ctx, issuer_endpoint_url);
	s.serialize(ctx, security_policy_uri);
}

void opc_ua::UserTokenPolicy::unserialize(SerializationContext& ctx, Serializer& s)
{
	UInt32 token_type_i;

	s.unserialize(ctx, policy_id);
	s.unserialize(ctx, token_type_i);
	s.unserialize(ctx, issued_token_type);
	s.unserialize(ctx, issuer_endpoint_url);
	s.unserialize(ctx, security_policy_uri);

	token_type = static_cast<UserTokenType>(token_type_i);
}

opc_ua::EndpointDescription::EndpointDescription()
	: endpoint_url(), server(), server_certificate(),
	security_mode(), security_policy_uri(), user_identity_tokens(),
	transport_profile_uri(), security_level()
{
}

void opc_ua::EndpointDescription::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, endpoint_url);
	s.serialize(ctx, server);
	s.serialize(ctx, server_certificate);
	s.serialize(ctx, static_cast<UInt32>(security_mode));
	s.serialize(ctx, security_policy_uri);
	s.serialize(ctx, ArraySerialization<UserTokenPolicy>(user_identity_tokens));
	s.serialize(ctx, transport_profile_uri);
	s.serialize(ctx, security_level);
}

void opc_ua::EndpointDescription::unserialize(SerializationContext& ctx, Serializer& s)
{
	UInt32 security_mode_i;

	s.unserialize(ctx, endpoint_url);
	s.unserialize(ctx, server);
	s.unserialize(ctx, server_certificate);
	s.unserialize(ctx, security_mode_i);
	s.unserialize(ctx, security_policy_uri);
	s.unserialize(ctx, ArrayUnserialization<UserTokenPolicy>(user_identity_tokens));
	s.unserialize(ctx, transport_profile_uri);
	s.unserialize(ctx, security_level);

	security_mode = static_cast<MessageSecurityMode>(security_mode_i);
}

opc_ua::SignedSoftwareCertificate::SignedSoftwareCertificate()
{
}

void opc_ua::SignedSoftwareCertificate::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, certificate_data);
	s.serialize(ctx, signature);
}

void opc_ua::SignedSoftwareCertificate::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, certificate_data);
	s.unserialize(ctx, signature);
}

opc_ua::SignatureData::SignatureData()
	: algorithm(), signature()
{
}

void opc_ua::SignatureData::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, algorithm);
	s.serialize(ctx, signature);
}

void opc_ua::SignatureData::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, algorithm);
	s.unserialize(ctx, signature);
}

opc_ua::CreateSessionResponse::CreateSessionResponse()
{
}

void opc_ua::CreateSessionResponse::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
	s.serialize(ctx, session_id);
	s.serialize(ctx, authentication_token);
	s.serialize(ctx, revised_session_timeout);
	s.serialize(ctx, server_nonce);
	s.serialize(ctx, server_certificate);
	s.serialize(ctx, ArraySerialization<EndpointDescription>(server_endpoints));
	s.serialize(ctx, ArraySerialization<SignedSoftwareCertificate>(server_software_certificates));
	s.serialize(ctx, server_signature);
	s.serialize(ctx, max_request_message_size);
}

void opc_ua::CreateSessionResponse::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
	s.unserialize(ctx, session_id);
	s.unserialize(ctx, authentication_token);
	s.unserialize(ctx, revised_session_timeout);
	s.unserialize(ctx, server_nonce);
	s.unserialize(ctx, server_certificate);
	s.unserialize(ctx, ArrayUnserialization<EndpointDescription>(server_endpoints));
	s.unserialize(ctx, ArrayUnserialization<SignedSoftwareCertificate>(server_software_certificates));
	s.unserialize(ctx, server_signature);
	s.unserialize(ctx, max_request_message_size);
}

opc_ua::CloseSessionRequest::CloseSessionRequest()
{
}

opc_ua::CloseSessionRequest::CloseSessionRequest(Boolean del_subscriptions)
	: delete_subscriptions(del_subscriptions)
{
}

void opc_ua::CloseSessionRequest::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, delete_subscriptions);
}

void opc_ua::CloseSessionRequest::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, request_header);
	s.unserialize(ctx, delete_subscriptions);
}

opc_ua::CloseSessionResponse::CloseSessionResponse()
{
}

void opc_ua::CloseSessionResponse::serialize(SerializationContext& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
}

void opc_ua::CloseSessionResponse::unserialize(SerializationContext& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
}
