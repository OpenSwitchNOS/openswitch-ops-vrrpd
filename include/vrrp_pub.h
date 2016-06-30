/* VRRP CLI commands
 *
 * Copyright (C)2016 Hewlett Packard Enterprise Development LP
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * File: vrrp_pub.h
 *
 * Purpose:  To define VRRP definitions that are used by both protocol and cli.
 */

#define VRRP_MAX_VRS_PER_IFACE   32      /* Max. no. of virtual routers per interface */
#define VRRP_MAX_VRS_PER_RTR    512     /* Max. no. of virtual routers per Router */
#define VRRP_MAX_IPS_PER_VR     32      /* Max. no. of IP addresses per virtual router */
#define VRRP_MAX_VIPS_ON_ROUTER 2048  /* Max. no. of virtual ip address on Router */
#define VRRP_MAX_TRACK_ENTITIES_PER_RTR    (128)    /* Max. no. of track entities per Router */

#define VRRP_IPV4_MAX_LEN 32
#define VRRP_IPV6_MAX_LEN 128

#define VRRP_VR_NAME_LENGTH 8

#define VRRP_MAX_PORT_NAME_LENGTH 50   /* Max port name string length */
#define VRRP_MAX_ADDR_FAMILY_NAME_LENGTH 5 /* Max address family name length*/

#define VRRP_MIN_VRID           1       /* Min. value of VRID */
#define VRRP_MAX_VRID           255     /* Max. value of VRID */
#define VRRP_INVALID_VRID	     0	    /* Invalid VRID */

#define IS_VALID_VRID(vrid)     ((vrid >= VRRP_MIN_VRID) && (vrid <= VRRP_MAX_VRID))
#define IS_VALID_INETTYPE(inetType) ((inetType >= 1) && (inetType <= 2))

#define VRRP_VERSION_2      2          /* VRRP version 2 -- rfc2338.5.3.1 */
#define VRRP_VERSION_3      3          /* VRRP version 3 -- rfc5798.5.2.1 */

#define VRRP_MIN_BACKUP_VR_PTY  1       /* Min. value of priority assigned to a Backup VR */
#define VRRP_MAX_BACKUP_VR_PTY  254     /* Max. value of priority assigned to a Backup VR */

#define VRRP_MIN_PREEMPT_DELAY  1       /* Min. value of preemptive delay time  */
#define VRRP_MAX_PREEMPT_DELAY  600     /* Max. value of preemptive delay time  */

#define VRRP_OWNER_VR_PTY       255     /* Value of priority assigned to Owner VR */

#define VRRP_RELEASE_PTY        0       /* Value of priority to indicate loss of control */

/* Default values */

#define VRRP_DEF_BACKUP_VR_PTY  100     /* Default value of Backup VR priority */
#define VRRP_DEF_ADVT_INTERVAL  1       /* Default value of VR advertisement interval */

#define VRRP_LOW_PTY_RTR_SKEW_TIME  1   /* Skew time for a router whose priority <
                                           default priority*/

/* these enumerations correspond to RFC 4001.
 * typed IP addresses.
 */
typedef enum _InetAddressType
{     unknownType = 0,
      ipv4Type    = 1,
      ipv6Type    = 2,
      ipv4zType   = 3,
      ipv6zType   = 4,
      dnsType     = 16
} InetAddressType;

#define VRRP_OVSDB_TXN_CREATE_ERROR "Couldn't create the OVSDB transaction.Function=%s Line=%d"
#define VRRP_OVSDB_ROW_FETCH_ERROR  "Couldn't fetch row from the DB.Function=%s Line=%d"
#define VRRP_OVSDB_TXN_COMMIT_ERROR "Committing transaction to DB failed.Function=%s Line=%d"
/* VRRP timers */
#define VRRP_TIMER_KEY_ADVERTISE_INTERVAL      "advertise_interval"
#define VRRP_TIMER_KEY_PREEMPT_DELAY_TIME      "preempt_delay_time"
#define VRRP_TIMER_KEY_MAX_LENGTH              80
#define VRRP_MAX_TIMERS                        2