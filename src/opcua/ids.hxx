/* OPC UA protocol implementation
 * (c) 2014 Michał Górny
 * Licensed under the terms of the 2-clause BSD license
 */

#pragma once

#ifndef IDS_HXX
#define IDS_HXX 1

namespace opc_ua
{
	// TODO: namespace this, different encodings use different ids...
	enum class NumericNodeId
	{
		NONE = 0,

		OPEN_SECURE_CHANNEL_REQUEST = 446,
		OPEN_SECURE_CHANNEL_RESPONSE = 449,
	};
};

#endif /*IDS_HXX*/
