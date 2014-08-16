/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_TCP_IDMAPPING_HXX
#define OPCUA_TCP_IDMAPPING_HXX 1

#include <opcua/common/types.hxx>

#include <unordered_map>

namespace opc_ua
{
	namespace tcp
	{
		typedef std::unordered_map<UInt32, UInt32> NodeIdMappingType;
		extern const NodeIdMappingType id_mapping;
		extern const NodeIdMappingType reverse_id_mapping;
	};
};

#endif /*OPCUA_TCP_IDMAPPING_HXX*/
