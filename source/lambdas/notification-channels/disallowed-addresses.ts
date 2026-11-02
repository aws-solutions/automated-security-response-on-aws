// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { BlockList, isIP } from 'node:net';
import { normalizeHostname } from '@asr/data-models';

/** Non-public IPv4 ranges a channel request must never reach. */
const DISALLOWED_IPV4_SUBNETS: ReadonlyArray<readonly [network: string, prefixLength: number]> = [
  ['0.0.0.0', 8], // this network
  ['10.0.0.0', 8], // RFC1918
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, incl. the instance metadata service
  ['172.16.0.0', 12], // RFC1918
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.168.0.0', 16], // RFC1918
  ['198.18.0.0', 15], // benchmarking
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved, incl. 255.255.255.255
];

/** Non-public IPv6 ranges that do not embed an IPv4 address. */
const DISALLOWED_IPV6_SUBNETS: ReadonlyArray<readonly [network: string, prefixLength: number]> = [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['fe80::', 10], // link-local
  ['fec0::', 10], // deprecated site-local
  ['fc00::', 7], // unique-local, incl. fd00:ec2::254 (instance metadata service)
  ['2001::', 32], // Teredo
  ['ff00::', 8], // multicast
];

/**
 * IPv6 prefixes that carry an IPv4 address in the low 32 bits. BlockList matches IPv4-mapped addresses
 * against IPv4 rules itself; the prefix is listed anyway so the check does not depend on that.
 */
const IPV4_IN_LOW_32_BITS_PREFIXES: readonly string[] = ['::ffff:', '::', '64:ff9b::'];

function toHexGroups(ipv4: string): string {
  const [first, second, third, fourth] = ipv4.split('.').map(Number);
  return `${((first << 8) | second).toString(16)}:${((third << 8) | fourth).toString(16)}`;
}

function buildDisallowedAddresses(): BlockList {
  const blockList = new BlockList();
  for (const [network, prefixLength] of DISALLOWED_IPV4_SUBNETS) {
    blockList.addSubnet(network, prefixLength, 'ipv4');
    for (const prefix of IPV4_IN_LOW_32_BITS_PREFIXES) {
      blockList.addSubnet(`${prefix}${network}`, 96 + prefixLength, 'ipv6');
    }
    // 6to4 (2002::/16) carries the IPv4 address in bits 16 to 47.
    blockList.addSubnet(`2002:${toHexGroups(network)}::`, 16 + prefixLength, 'ipv6');
  }
  for (const [network, prefixLength] of DISALLOWED_IPV6_SUBNETS) {
    blockList.addSubnet(network, prefixLength, 'ipv6');
  }
  return blockList;
}

const DISALLOWED_ADDRESSES = buildDisallowedAddresses();

/**
 * Whether a URL hostname or a resolved address is `localhost` or an IP address in a non-public range:
 * loopback, link-local, instance metadata, private, CGNAT, multicast, reserved, and the IPv6 forms that
 * embed those IPv4 ranges (IPv4-mapped, IPv4-compatible, NAT64, 6to4). Returns false for any other
 * hostname; names are checked again after DNS resolution.
 */
export function isDisallowedAddress(host: string): boolean {
  const normalized = normalizeHostname(host);
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return true;

  const family = isIP(normalized);
  if (family === 0) return false;
  try {
    return DISALLOWED_ADDRESSES.check(normalized, family === 4 ? 'ipv4' : 'ipv6');
  } catch {
    // An address isIP accepts but BlockList cannot parse (for example a zone ID) is refused.
    return true;
  }
}
