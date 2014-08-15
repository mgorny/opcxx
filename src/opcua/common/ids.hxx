/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_IDS_HXX
#define OPCUA_COMMON_IDS_HXX 1

#include <opcua/common/struct.hxx>

#include <stdexcept>

namespace opc_ua
{
	template <typename T>
	constexpr inline UInt32 NumericNodeId(const T&)
	{
		return 0;
	}

	template <>
	constexpr inline UInt32 NumericNodeId(const OpenSecureChannelRequest& T) { return 444; }
	template <>
	constexpr inline UInt32 NumericNodeId(const OpenSecureChannelResponse& T) { return 447; }
	template <>
	constexpr inline UInt32 NumericNodeId(const CloseSecureChannelRequest& T) { return 450; }
	template <>
	constexpr inline UInt32 NumericNodeId(const CloseSecureChannelResponse& T) { return 453; }
};

#endif /*OPCUA_COMMON_IDS_HXX*/
