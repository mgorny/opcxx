/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "struct.hxx"

template <class T>
constexpr opc_ua::Struct* struct_constructor()
{
	return new T;
}

template <class T>
constexpr opc_ua::StructConstructorMap::value_type M()
{
	return {T::NODE_ID, struct_constructor<T>};
}

const opc_ua::StructConstructorMap opc_ua::struct_constructors{
	M<ActivateSessionRequest>(),
	M<ActivateSessionResponse>(),
	M<AnonymousIdentityToken>(),
	M<ApplicationDescription>(),
	M<BrowsePath>(),
	M<ChannelSecurityToken>(),
	M<CloseSecureChannelRequest>(),
	M<CloseSecureChannelResponse>(),
	M<CloseSessionRequest>(),
	M<CloseSessionResponse>(),
	M<CreateSessionRequest>(),
	M<CreateSessionResponse>(),
	M<DataValue>(),
	M<DiagnosticInfo>(),
	M<EndpointDescription>(),
	M<OpenSecureChannelRequest>(),
	M<OpenSecureChannelResponse>(),
	M<QualifiedName>(),
	M<ReadRequest>(),
	M<ReadResponse>(),
	M<ReadValueId>(),
	M<RelativePath>(),
	M<RelativePathElement>(),
	M<RequestHeader>(),
	M<ResponseHeader>(),
	M<SignatureData>(),
	M<SignedSoftwareCertificate>(),
	M<TranslateBrowsePathsToNodeIdsRequest>(),
	M<UserIdentityToken>(),
	M<UserTokenPolicy>(),
};

opc_ua::RequestHeader::RequestHeader()
	: authentication_token(), timestamp(),
	request_handle(0), return_diagnostics(0),
	audit_entry_id(), timeout_hint(0), additional_header()
{
}

void opc_ua::RequestHeader::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, authentication_token);
	s.serialize(ctx, timestamp);
	s.serialize(ctx, request_handle);
	s.serialize(ctx, return_diagnostics);
	s.serialize(ctx, audit_entry_id);
	s.serialize(ctx, timeout_hint);
	s.serialize(ctx, additional_header);
}

void opc_ua::RequestHeader::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
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
	: flags(0)
{
}

void opc_ua::DiagnosticInfo::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, flags);
}

void opc_ua::DiagnosticInfo::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, flags);
}

opc_ua::ResponseHeader::ResponseHeader()
	: timestamp(), request_handle(0), service_result(0),
	service_diagnostics(), string_table(), additional_header()
{
}

void opc_ua::ResponseHeader::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, timestamp);
	s.serialize(ctx, request_handle);
	s.serialize(ctx, service_result);
	s.serialize(ctx, service_diagnostics);
	s.serialize(ctx, ArraySerialization<String>(string_table));
	s.serialize(ctx, additional_header);
}

void opc_ua::ResponseHeader::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, timestamp);
	s.unserialize(ctx, request_handle);
	s.unserialize(ctx, service_result);
	s.unserialize(ctx, service_diagnostics);
	s.unserialize(ctx, ArrayUnserialization<String>(string_table));
	s.unserialize(ctx, additional_header);
}

opc_ua::OpenSecureChannelRequest::OpenSecureChannelRequest(SecurityTokenRequestType req_type, MessageSecurityMode req_mode, ByteString req_nonce, UInt32 req_lifetime)
	: client_protocol_version(0),
	request_type(req_type),
	security_mode(req_mode),
	client_nonce(req_nonce),
	requested_lifetime(req_lifetime)
{
}

void opc_ua::OpenSecureChannelRequest::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, client_protocol_version);
	s.serialize(ctx, static_cast<UInt32>(request_type));
	s.serialize(ctx, static_cast<UInt32>(security_mode));
	s.serialize(ctx, client_nonce);
	s.serialize(ctx, requested_lifetime);
}

void opc_ua::OpenSecureChannelRequest::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
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
	: channel_id(0), token_id(0), created_at(), revised_lifetime(0)
{
}

void opc_ua::ChannelSecurityToken::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, channel_id);
	s.serialize(ctx, token_id);
	s.serialize(ctx, created_at);
	s.serialize(ctx, revised_lifetime);
}

void opc_ua::ChannelSecurityToken::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, channel_id);
	s.unserialize(ctx, token_id);
	s.unserialize(ctx, created_at);
	s.unserialize(ctx, revised_lifetime);
}

opc_ua::OpenSecureChannelResponse::OpenSecureChannelResponse()
	: server_protocol_version(0), security_token(), server_nonce("")
{
}

void opc_ua::OpenSecureChannelResponse::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
	s.serialize(ctx, server_protocol_version);
	s.serialize(ctx, security_token);
	s.serialize(ctx, server_nonce);
}

void opc_ua::OpenSecureChannelResponse::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
	s.unserialize(ctx, server_protocol_version);
	s.unserialize(ctx, security_token);
	s.unserialize(ctx, server_nonce);
}

opc_ua::CloseSecureChannelRequest::CloseSecureChannelRequest()
{
}

void opc_ua::CloseSecureChannelRequest::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
}

void opc_ua::CloseSecureChannelRequest::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, request_header);
}

opc_ua::CloseSecureChannelResponse::CloseSecureChannelResponse()
{
}

void opc_ua::CloseSecureChannelResponse::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
}

void opc_ua::CloseSecureChannelResponse::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
}

opc_ua::ApplicationDescription::ApplicationDescription(ApplicationType app_type)
	: application_uri(), product_uri(),
	application_name(), application_type(app_type),
	gateway_server_uri(), discovery_profile_uri(),
	discovery_urls()
{
}

void opc_ua::ApplicationDescription::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, application_uri);
	s.serialize(ctx, product_uri);
	s.serialize(ctx, application_name);
	s.serialize(ctx, static_cast<UInt32>(application_type));
	s.serialize(ctx, gateway_server_uri);
	s.serialize(ctx, discovery_profile_uri);
	s.serialize(ctx, ArraySerialization<String>(discovery_urls));
}

void opc_ua::ApplicationDescription::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
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

void opc_ua::CreateSessionRequest::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
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

void opc_ua::CreateSessionRequest::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
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

void opc_ua::UserTokenPolicy::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, policy_id);
	s.serialize(ctx, static_cast<UInt32>(token_type));
	s.serialize(ctx, issued_token_type);
	s.serialize(ctx, issuer_endpoint_url);
	s.serialize(ctx, security_policy_uri);
}

void opc_ua::UserTokenPolicy::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
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
	transport_profile_uri(), security_level(0)
{
}

void opc_ua::EndpointDescription::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
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

void opc_ua::EndpointDescription::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
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
	: certificate_data(), signature()
{
}

void opc_ua::SignedSoftwareCertificate::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, certificate_data);
	s.serialize(ctx, signature);
}

void opc_ua::SignedSoftwareCertificate::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, certificate_data);
	s.unserialize(ctx, signature);
}

opc_ua::SignatureData::SignatureData()
	: algorithm(), signature()
{
}

void opc_ua::SignatureData::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, algorithm);
	s.serialize(ctx, signature);
}

void opc_ua::SignatureData::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, algorithm);
	s.unserialize(ctx, signature);
}

opc_ua::CreateSessionResponse::CreateSessionResponse()
	: session_id(), authentication_token(), revised_session_timeout(0),
	server_nonce(), server_certificate(), server_endpoints(),
	server_software_certificates(), server_signature(),
	max_request_message_size(0x1000000)
{
}

void opc_ua::CreateSessionResponse::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
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

void opc_ua::CreateSessionResponse::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
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

opc_ua::ActivateSessionRequest::ActivateSessionRequest()
	: client_signature(), client_software_certificates(), locale_ids(),
	user_identity_token(), user_token_signature()
{
}

void opc_ua::ActivateSessionRequest::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, client_signature);
	s.serialize(ctx, ArraySerialization<SignedSoftwareCertificate>(client_software_certificates));
	s.serialize(ctx, ArraySerialization<String>(locale_ids));
	s.serialize(ctx, user_identity_token);
	s.serialize(ctx, user_token_signature);
}

void opc_ua::ActivateSessionRequest::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, request_header);
	s.unserialize(ctx, client_signature);
	s.unserialize(ctx, ArrayUnserialization<SignedSoftwareCertificate>(client_software_certificates));
	s.unserialize(ctx, ArrayUnserialization<String>(locale_ids));
	s.unserialize(ctx, user_identity_token);
	s.unserialize(ctx, user_token_signature);
}

opc_ua::ActivateSessionResponse::ActivateSessionResponse()
	: server_nonce(), results(), diagnostic_infos()
{
}

void opc_ua::ActivateSessionResponse::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
	s.serialize(ctx, server_nonce);
	s.serialize(ctx, ArraySerialization<StatusCode>(results));
	s.serialize(ctx, ArraySerialization<DiagnosticInfo>(diagnostic_infos));
}

void opc_ua::ActivateSessionResponse::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
	s.unserialize(ctx, server_nonce);
	s.unserialize(ctx, ArrayUnserialization<StatusCode>(results));
	s.unserialize(ctx, ArrayUnserialization<DiagnosticInfo>(diagnostic_infos));
}

opc_ua::CloseSessionRequest::CloseSessionRequest(Boolean del_subscriptions)
	: delete_subscriptions(del_subscriptions)
{
}

void opc_ua::CloseSessionRequest::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, delete_subscriptions);
}

void opc_ua::CloseSessionRequest::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, request_header);
	s.unserialize(ctx, delete_subscriptions);
}

opc_ua::CloseSessionResponse::CloseSessionResponse()
{
}

void opc_ua::CloseSessionResponse::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
}

void opc_ua::CloseSessionResponse::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
}

opc_ua::QualifiedName::QualifiedName(CharArray new_name, UInt16 ns_index)
	: namespace_index(ns_index), name(new_name)
{
}

void opc_ua::QualifiedName::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, namespace_index);
	s.serialize(ctx, name);
}

void opc_ua::QualifiedName::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, namespace_index);
	s.unserialize(ctx, name);
}

opc_ua::RelativePathElement::RelativePathElement(NodeId ref_type, Boolean is_inv, Boolean inc_subtypes, QualifiedName target)
	: reference_type_id(ref_type), is_inverse(is_inv), include_subtypes(inc_subtypes), target_name(target)
{
}

void opc_ua::RelativePathElement::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, reference_type_id);
	s.serialize(ctx, is_inverse);
	s.serialize(ctx, include_subtypes);
	s.serialize(ctx, target_name);
}

void opc_ua::RelativePathElement::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, reference_type_id);
	s.unserialize(ctx, is_inverse);
	s.unserialize(ctx, include_subtypes);
	s.unserialize(ctx, target_name);
}

opc_ua::RelativePath::RelativePath(Array<RelativePathElement> new_elements)
	: elements(new_elements)
{
}

void opc_ua::RelativePath::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, ArraySerialization<RelativePathElement>(elements));
}

void opc_ua::RelativePath::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, ArrayUnserialization<RelativePathElement>(elements));
}

opc_ua::BrowsePath::BrowsePath(NodeId start, RelativePath path)
	: starting_node(start), relative_path(path)
{
}

void opc_ua::BrowsePath::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, starting_node);
	s.serialize(ctx, relative_path);
}

void opc_ua::BrowsePath::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, starting_node);
	s.unserialize(ctx, relative_path);
}

opc_ua::TranslateBrowsePathsToNodeIdsRequest::TranslateBrowsePathsToNodeIdsRequest(Array<BrowsePath> paths)
	: browse_paths(paths)
{
}

void opc_ua::TranslateBrowsePathsToNodeIdsRequest::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, ArraySerialization<BrowsePath>(browse_paths));
}

void opc_ua::TranslateBrowsePathsToNodeIdsRequest::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, request_header);
	s.unserialize(ctx, ArrayUnserialization<BrowsePath>(browse_paths));
}

opc_ua::ReadValueId::ReadValueId()
	: node_id(), attribute_id(0), index_range(), data_encoding()
{
}

void opc_ua::ReadValueId::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, node_id);
	s.serialize(ctx, attribute_id);
	s.serialize(ctx, index_range);
	s.serialize(ctx, data_encoding);
}

void opc_ua::ReadValueId::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, node_id);
	s.unserialize(ctx, attribute_id);
	s.unserialize(ctx, index_range);
	s.unserialize(ctx, data_encoding);
}

opc_ua::ReadRequest::ReadRequest()
	: max_age(0), timestamps_to_return(TimestampsToReturn::SOURCE), nodes_to_read()
{
}

void opc_ua::ReadRequest::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, request_header);
	s.serialize(ctx, max_age);
	s.serialize(ctx, static_cast<UInt32>(timestamps_to_return));
	s.serialize(ctx, ArraySerialization<ReadValueId>(nodes_to_read));
}

void opc_ua::ReadRequest::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	UInt32 timestamps_to_return_i;

	s.unserialize(ctx, request_header);
	s.unserialize(ctx, max_age);
	s.unserialize(ctx, timestamps_to_return_i);
	s.unserialize(ctx, ArrayUnserialization<ReadValueId>(nodes_to_read));

	timestamps_to_return = static_cast<TimestampsToReturn>(timestamps_to_return_i);
}

opc_ua::DataValue::DataValue()
	: flags(0), value(), status_code(0), source_timestamp(), source_picoseconds(0), server_timestamp(), server_picoseconds(0)
{
}

void opc_ua::DataValue::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, flags);
	if (flags & static_cast<Byte>(DataValueFlags::VALUE_SPECIFIED))
		s.serialize(ctx, value);
	if (flags & static_cast<Byte>(DataValueFlags::STATUS_CODE_SPECIFIED))
		s.serialize(ctx, status_code);
	if (flags & static_cast<Byte>(DataValueFlags::SOURCE_TIMESTAMP_SPECIFIED))
		s.serialize(ctx, source_timestamp);
	if (flags & static_cast<Byte>(DataValueFlags::SOURCE_PICOSECONDS_SPECIFIED))
		s.serialize(ctx, source_picoseconds);
	if (flags & static_cast<Byte>(DataValueFlags::SERVER_TIMESTAMP_SPECIFIED))
		s.serialize(ctx, server_timestamp);
	if (flags & static_cast<Byte>(DataValueFlags::SERVER_PICOSECONDS_SPECIFIED))
		s.serialize(ctx, server_picoseconds);
}

void opc_ua::DataValue::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, flags);
	if (flags & static_cast<Byte>(DataValueFlags::VALUE_SPECIFIED))
		s.unserialize(ctx, value);
	if (flags & static_cast<Byte>(DataValueFlags::STATUS_CODE_SPECIFIED))
		s.unserialize(ctx, status_code);
	if (flags & static_cast<Byte>(DataValueFlags::SOURCE_TIMESTAMP_SPECIFIED))
		s.unserialize(ctx, source_timestamp);
	if (flags & static_cast<Byte>(DataValueFlags::SOURCE_PICOSECONDS_SPECIFIED))
		s.unserialize(ctx, source_picoseconds);
	if (flags & static_cast<Byte>(DataValueFlags::SERVER_TIMESTAMP_SPECIFIED))
		s.unserialize(ctx, server_timestamp);
	if (flags & static_cast<Byte>(DataValueFlags::SERVER_PICOSECONDS_SPECIFIED))
		s.unserialize(ctx, server_picoseconds);
}

opc_ua::ReadResponse::ReadResponse()
	: results(), diagnostic_infos()
{
}

void opc_ua::ReadResponse::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, response_header);
	s.serialize(ctx, ArraySerialization<DataValue>(results));
	s.serialize(ctx, ArraySerialization<DiagnosticInfo>(diagnostic_infos));
}

void opc_ua::ReadResponse::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, response_header);
	s.unserialize(ctx, ArrayUnserialization<DataValue>(results));
	s.unserialize(ctx, ArrayUnserialization<DiagnosticInfo>(diagnostic_infos));
}

opc_ua::UserIdentityToken::UserIdentityToken(String new_policy_id)
	: policy_id(new_policy_id)
{
}

void opc_ua::UserIdentityToken::serialize(WritableSerializationBuffer& ctx, Serializer& s) const
{
	s.serialize(ctx, policy_id);
}

void opc_ua::UserIdentityToken::unserialize(ReadableSerializationBuffer& ctx, Serializer& s)
{
	s.unserialize(ctx, policy_id);
}

opc_ua::AnonymousIdentityToken::AnonymousIdentityToken()
	: UserIdentityToken("anonPolicy")
{
}
