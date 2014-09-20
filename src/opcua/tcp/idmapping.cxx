/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "idmapping.hxx"

#include <opcua/common/struct.hxx>

const opc_ua::tcp::NodeIdMappingType opc_ua::tcp::id_mapping{
	{UserTokenPolicy::NODE_ID, 306},
	{ApplicationDescription::NODE_ID, 310},
	{EndpointDescription::NODE_ID, 314},
	{UserIdentityToken::NODE_ID, 318},
	{AnonymousIdentityToken::NODE_ID, 321},
	{SignedSoftwareCertificate::NODE_ID, 346},
	{RequestHeader::NODE_ID, 391},
	{ResponseHeader::NODE_ID, 394},
	{ChannelSecurityToken::NODE_ID, 443},
	{OpenSecureChannelRequest::NODE_ID, 446},
	{OpenSecureChannelResponse::NODE_ID, 449},
	{CloseSecureChannelRequest::NODE_ID, 452},
	{CloseSecureChannelResponse::NODE_ID, 455},
	{SignatureData::NODE_ID, 458},
	{CreateSessionRequest::NODE_ID, 461},
	{CreateSessionResponse::NODE_ID, 464},
	{ActivateSessionRequest::NODE_ID, 467},
	{ActivateSessionResponse::NODE_ID, 470},
	{CloseSessionRequest::NODE_ID, 473},
	{CloseSessionResponse::NODE_ID, 476},
	{RelativePathElement::NODE_ID, 539},
	{RelativePath::NODE_ID, 542},
	{BrowsePath::NODE_ID, 545},
	{TranslateBrowsePathsToNodeIdsRequest::NODE_ID, 554},
	{ReadValueId::NODE_ID, 628},
	{ReadRequest::NODE_ID, 631},
	{ReadResponse::NODE_ID, 634},
	{WriteValue::NODE_ID, 670},
	{WriteRequest::NODE_ID, 673},
	{WriteResponse::NODE_ID, 676},
};

class reverse_map_iterator : public opc_ua::tcp::NodeIdMappingType::const_iterator
{
public:
	typedef opc_ua::tcp::NodeIdMappingType::const_iterator const_orig_iterator;

	reverse_map_iterator(const_orig_iterator it)
		: opc_ua::tcp::NodeIdMappingType::const_iterator(std::move(it))
	{
	}

	const value_type operator*() const
	{
		const value_type& v = const_orig_iterator::operator*();

		return {v.second, v.first};
	}
};

const opc_ua::tcp::NodeIdMappingType opc_ua::tcp::reverse_id_mapping{
	reverse_map_iterator(id_mapping.cbegin()), reverse_map_iterator(id_mapping.cend())
};
