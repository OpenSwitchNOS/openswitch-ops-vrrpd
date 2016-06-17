/*
 * Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
 * All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 * File: vrrp_ip.h
 *
 */
#ifndef __VRRP_IP_H__
#define __VRRP_IP_H__

#include <netinet/ip.h>

typedef uint32_t IP_ADDRESS;

typedef union
{
   struct sockaddr_in6 ipv6;
   struct sockaddr_in  ipv4;
} SOCKADDR_STORAGE_T;

/* IPv4 prefix structure. */
struct prefix_ipv4
{
  uint8_t family;
  uint8_t prefixlen;
  struct in_addr prefix __attribute__ ((aligned (8)));
};

/* IPv6 prefix structure. */
struct prefix_ipv6
{
  uint8_t family;
  uint8_t prefixlen;
  struct in6_addr prefix __attribute__ ((aligned (8)));
};

#ifdef INET6
#define ss_len      ipv6.sin6_len
#define ss_family   ipv6.sin6_family
#define ss_port     ipv6.sin6_port
#else
#define ss_len      ipv4.sin_len
#define ss_family   ipv4.sin_family
#define ss_port     ipv4.sin_port
#endif /* INET6 */

#define IP_PREFIXLEN_TO_MASK(m)   \
   ((IP_ADDRESS)((IP_ADDRESS_BCAST >> (32 - (m))) << (32 - (m))))
#define IP_MASK_TO_PREFIXLEN(m)   ((m == 0) ? 0 : (32 - sw_ffs( ~(m) + 1 )) )

typedef struct ip IP_HDR;

/* function declarations */
bool iputilSockaddrIsLinkLocal(const SOCKADDR_STORAGE_T *ipAddr);
bool isLinkLocal(struct in6_addr *ipv6);

#define IP_ADDRESS_NULL   ((IP_ADDRESS)0L)
#define IP_ADDRESS_BCAST  ((IP_ADDRESS)0xffffffff)

#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16

#define IPV4_ADDRSTRLEN     16
#define IPV4_PREFIX_SIZE    18

#define IPV6_ADDRSTRLEN    46
#define IPV6_PREFIX_SIZE   49

#define VR_IP_ADDRESS_LENGTH 45

/* IPv4 offset flags */
#define IP_CE           0x8000          /* Flag: "Congestion"           */
#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

#define IP_OFFSET_NBO   0xFF1F          /* "Fragment Offset" part, NBO   */
#define IP_DF_NBO       0x0040          /* NBO version of don't fragment */
#define IP_MF_NBO       0x0020          /* NBO version of more fragments */

/* these enumerations correspond to the OctetString
 * length values for the appropriate address types.
 * see RFC 4001.
 */
typedef enum _InetAddressSize
   {  unknownSize = 0,
      ipv4Size    = 4,
      ipv6Size    = 16,
      ipv4zSize   = 8,
      ipv6zSize   = 20,
      dnsSize     = 255 /* valid length is 1..256 */
} InetAddressSize;

typedef enum {
   IPV6_ADDR_UNKNOWN,
   IPV6_ADDR_TENTATIVE,
   IPV6_ADDR_DUPLICATE,
   IPV6_ADDR_PREFERRED,
   IPV6_ADDR_DEPRECATED
} IPV6_ADDRESS_STATE;

#define IPV6_VERSION     0x60
#define IPV6_MAXHLIM     255 /* maximum hoplimit */
#define IPV6_DEFHLIM     64  /* default hlim */
#define IPV6_FRAGTTL     120 /* ttl for fragment packets, in slowtimo tick */
#define IPV6_HLIMDEC     1   /* subtracted when forwarding */
#define IPV6_TYPE        0x86DD    /* IPv6 Type                         */

/**externs**/
extern SOCKADDR_STORAGE_T* vrrp_iputil_ipv4_to_sockaddr(struct in_addr *ipaddr,
                                                        SOCKADDR_STORAGE_T* sin);
extern SOCKADDR_STORAGE_T* vrrp_iputil_ipv4_to_sockaddr(struct in_addr *ipaddr,
                                                        SOCKADDR_STORAGE_T* sin);
extern bool vrrp_iputil_prefixlen_to_sockaddr(int addrFamily, uint8_t prefixLen,
                                       SOCKADDR_STORAGE_T *ss);
extern void vrrp_iputil_mask_sockaddr(const SOCKADDR_STORAGE_T* ip,
                                      const SOCKADDR_STORAGE_T *mask,
                                      SOCKADDR_STORAGE_T* maskedIp);
extern bool vrrp_iputil_sockaddr_equal(const SOCKADDR_STORAGE_T *ip1,
                                       const SOCKADDR_STORAGE_T *ip2);
extern void vrrp_iputil_sockaddr_copy(const SOCKADDR_STORAGE_T *src,
                                      SOCKADDR_STORAGE_T *dst);

#endif /*__VRRP_IP_H__ */
