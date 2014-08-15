/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_TCP_IDS_HXX
#define OPCUA_TCP_IDS_HXX 1

#include <opcua/common/ids.hxx>

namespace opc_ua
{
	namespace tcp
	{
		template <typename T>
		constexpr inline UInt32 NumericNodeIdBinary(const T& val)
		{
			return opc_ua::NumericNodeId(val);
		}

		template <>
		constexpr inline UInt32 NumericNodeIdBinary(const OpenSecureChannelRequest& T) { return 446; }
		template <>
		constexpr inline UInt32 NumericNodeIdBinary(const OpenSecureChannelResponse& T) { return 449; }
		template <>
		constexpr inline UInt32 NumericNodeIdBinary(const CloseSecureChannelRequest& T) { return 452; }
		template <>
		constexpr inline UInt32 NumericNodeIdBinary(const CloseSecureChannelResponse& T) { return 455; }
	};
};

#endif /*OPCUA_TCP_IDS_HXX*/
