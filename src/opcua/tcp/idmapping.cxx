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
	{OpenSecureChannelRequest::NODE_ID, 446},
	{OpenSecureChannelResponse::NODE_ID, 449},
	{CloseSecureChannelRequest::NODE_ID, 452},
	{CloseSecureChannelResponse::NODE_ID, 455},
	{CreateSessionRequest::NODE_ID, 461},
	{CreateSessionResponse::NODE_ID, 464},
	{ActivateSessionRequest::NODE_ID, 467},
	{ActivateSessionResponse::NODE_ID, 470},
	{CloseSessionRequest::NODE_ID, 473},
	{CloseSessionResponse::NODE_ID, 476},
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
