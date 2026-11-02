// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { isDisallowedAddress } from '../disallowed-addresses';

/** Each blocked IPv4 range with an address just inside it and the nearest public address just outside. */
const IPV4_RANGE_BOUNDARIES: ReadonlyArray<{
  readonly range: string;
  readonly inside: string[];
  readonly outside: string[];
}> = [
  { range: '0.0.0.0/8', inside: ['0.0.0.0', '0.255.255.255'], outside: ['1.0.0.0'] },
  { range: '10.0.0.0/8', inside: ['10.0.0.0', '10.255.255.255'], outside: ['9.255.255.255', '11.0.0.0'] },
  { range: '100.64.0.0/10', inside: ['100.64.0.0', '100.127.255.255'], outside: ['100.63.255.255', '100.128.0.0'] },
  { range: '127.0.0.0/8', inside: ['127.0.0.1', '127.255.255.255'], outside: ['126.255.255.255', '128.0.0.0'] },
  { range: '169.254.0.0/16', inside: ['169.254.0.0', '169.254.169.254'], outside: ['169.253.255.255', '169.255.0.0'] },
  { range: '172.16.0.0/12', inside: ['172.16.0.0', '172.31.255.255'], outside: ['172.15.255.255', '172.32.0.0'] },
  { range: '192.0.0.0/24', inside: ['192.0.0.0', '192.0.0.255'], outside: ['191.255.255.255', '192.0.1.0'] },
  { range: '192.168.0.0/16', inside: ['192.168.0.0', '192.168.255.255'], outside: ['192.167.255.255', '192.169.0.0'] },
  { range: '198.18.0.0/15', inside: ['198.18.0.0', '198.19.255.255'], outside: ['198.17.255.255', '198.20.0.0'] },
  { range: '224.0.0.0/4', inside: ['224.0.0.0', '239.255.255.255'], outside: ['223.255.255.255'] },
  { range: '240.0.0.0/4', inside: ['240.0.0.0', '255.255.255.255'], outside: [] },
];

/** Writes an IPv4 address as the two 16-bit hex groups IPv6 carries it in. */
function toHexGroups(ipv4: string): string {
  const [a, b, c, d] = ipv4.split('.').map(Number);
  return `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
}

/** Every IPv6 form that embeds an IPv4 address the check must look through. */
function embeddedForms(ipv4: string): string[] {
  const hex = toHexGroups(ipv4);
  return [
    `::ffff:${ipv4}`, // IPv4-mapped, dotted
    `::ffff:${hex}`, // IPv4-mapped, hex
    `::${ipv4}`, // IPv4-compatible
    `64:ff9b::${ipv4}`, // NAT64 well-known prefix
    `64:ff9b::${hex}`,
    `2002:${hex}::`, // 6to4
  ];
}

describe('isDisallowedAddress', () => {
  describe('IPv4 ranges', () => {
    it.each(IPV4_RANGE_BOUNDARIES)('blocks $range and allows the addresses just outside it', ({ inside, outside }) => {
      for (const address of inside) expect(isDisallowedAddress(address)).toBe(true);
      for (const address of outside) expect(isDisallowedAddress(address)).toBe(false);
    });
  });

  describe('IPv4 embedded in IPv6', () => {
    it.each(IPV4_RANGE_BOUNDARIES)('blocks $range in every embedded form', ({ inside }) => {
      for (const address of inside.flatMap(embeddedForms)) expect(isDisallowedAddress(address)).toBe(true);
    });

    it('allows the same embedded forms of a public IPv4 address', () => {
      for (const address of ['8.8.8.8', '1.1.1.1', '192.0.1.0', '198.20.0.0'].flatMap(embeddedForms)) {
        expect(isDisallowedAddress(address)).toBe(false);
      }
    });
  });

  describe('IPv6 ranges', () => {
    it('blocks unspecified, loopback, link-local, site-local, unique-local, Teredo, and multicast addresses', () => {
      const blocked = [
        '::',
        '::1',
        '0:0:0:0:0:0:0:1',
        'fe80::1',
        'febf:ffff::1',
        'fec0::1',
        'feff:ffff::1',
        'fc00::1',
        'fd00:ec2::254',
        'fdff:ffff::1',
        '2001::1',
        '2001:0:abcd::',
        'ff02::1',
        'ff0e::1',
        'ffff:ffff::1',
      ];
      for (const address of blocked) expect(isDisallowedAddress(address)).toBe(true);
    });

    it('allows public IPv6 addresses, including those next to the blocked ranges', () => {
      const allowed = [
        '2606:4700::1',
        '2001:4860:4860::8888',
        '2001:1::1',
        'fe7f:ffff::1',
        'fbff:ffff::1',
        '2001:db8::1',
      ];
      for (const address of allowed) expect(isDisallowedAddress(address)).toBe(false);
    });
  });

  describe('host forms', () => {
    it('blocks localhost names and bracketed, trailing-dot, or upper-case address forms', () => {
      const blocked = [
        'localhost',
        'localhost.',
        'LOCALHOST',
        'api.localhost',
        '[::1]',
        '[FD00:EC2::254]',
        '127.0.0.1.',
      ];
      for (const host of blocked) expect(isDisallowedAddress(host)).toBe(true);
    });

    it('does not treat ordinary hostnames or malformed addresses as blocked addresses', () => {
      const notAddresses = ['acme.service-now.com', 'example.com', '10.0.0.1.nip.io', '::ffff:300.1.1.1', ''];
      for (const host of notAddresses) expect(isDisallowedAddress(host)).toBe(false);
    });
  });
});
