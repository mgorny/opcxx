/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef OPCUA_COMMON_IDS_HXX
#define OPCUA_COMMON_IDS_HXX 1

namespace opc_ua
{
	// TODO: namespace this, different encodings use different ids...
	enum class NumericNodeId
	{
		NONE = 0,

		OPEN_SECURE_CHANNEL_REQUEST = 446,
		OPEN_SECURE_CHANNEL_RESPONSE = 449,
		CLOSE_SECURE_CHANNEL_REQUEST = 452,
		CLOSE_SECURE_CHANNEL_RESPONSE = 455,
	};
};

#endif /*OPCUA_COMMON_IDS_HXX*/
