#pragma once

#include <arpa/inet.h>
#include "mac.h"

/* ethernet addresses are 6 octets long */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN      0x6
#endif

#pragma pack(push, 1)
struct EthHdr final {

	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	Mac dmac() { return dmac_; }
	Mac smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }

	// Type(type_)
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
typedef EthHdr *PEthHdr; 
#pragma pack(pop)
