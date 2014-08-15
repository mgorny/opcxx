/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#ifdef HAVE_CONFIG_H
#	include "config.h"
#endif

#include "idmapping.hxx"

#include <opcua/common/struct.hxx>

std::unordered_map<opc_ua::UInt32, opc_ua::UInt32> opc_ua::tcp::id_mapping{
	{OpenSecureChannelRequest::NODE_ID, 446},
	{OpenSecureChannelResponse::NODE_ID, 449},
	{CloseSecureChannelRequest::NODE_ID, 452},
	{CloseSecureChannelResponse::NODE_ID, 455},
};
