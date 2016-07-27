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

#define VRRP_STATUS_KEY_STATE                            "state"
#define VRRP_STATUS_KEY_STATE_DURATION                   "state_duration"
#define VRRP_STATUS_KEY_MASTER_ROUTER                    "master_router"
#define VRRP_STATUS_KEY_IS_MASTER_LOCAL                  "is_master_local"
#define VRRP_STATUS_KEY_INIT_TO_MASTER_LAST_CHANGE       "init_to_master_last_change"
#define VRRP_STATUS_KEY_INIT_TO_BACKUP_LAST_CHANGE       "init_to_backup_last_change"
#define VRRP_STATUS_KEY_MASTER_TO_BACKUP_LAST_CHANGE     "master_to_backup_last_change"
#define VRRP_STATUS_KEY_BACKUP_TO_MASTER_LAST_CHANGE     "backup_to_master_last_change"
#define VRRP_STATUS_KEY_MASTER_TO_INIT_LAST_CHANGE       "master_to_init_last_change"
#define VRRP_STATUS_KEY_BACKUP_TO_INIT_LAST_CHANGE       "backup_to_init_last_change"

typedef enum _VrrpStatsKey
{
   VRRP_STATS_KEY_V3_TX = 0,
   VRRP_STATS_KEY_V3_RX,
   VRRP_STATS_KEY_V2_TX,
   VRRP_STATS_KEY_V2_RX,
   VRRP_STATS_KEY_ZERO_PRIORITY_RX,
   VRRP_STATS_KEY_ZERO_PRIORITY_TX,
   VRRP_STATS_KEY_V2_INCOMPATIBILITY,
   VRRP_STATS_KEY_MISMATCHED_ADDR_LIST_PKTS,
   VRRP_STATS_KEY_MISMATCHED_AUTH_TYPE_PKTS,
   VRRP_STATS_KEY_IP_ADDRESS_OWNER_CONFLICTS,
   VRRP_STATS_KEY_ADVERTISE_INTERVAL_ERRORS,
   VRRP_STATS_KEY_ADVERTISE_RECV_IN_INIT_STATE,
   VRRP_STATS_KEY_INVALID_GROUP,
   VRRP_STATS_KEY_OTHER_REASONS,
   VRRP_STATS_KEY_NEAR_FAILOVERS,
   VRRP_STATS_KEY_INIT_TO_MASTER,
   VRRP_STATS_KEY_INIT_TO_BACKUP,
   VRRP_STATS_KEY_BACKUP_TO_MASTER,
   VRRP_STATS_KEY_MASTER_TO_BACKUP,
   VRRP_STATS_KEY_MASTER_TO_INIT,
   VRRP_STATS_KEY_BACKUP_TO_INIT,
   VRRP_STATS_KEY_UNKNOWN
} VrrpStatsKey;

#define VRRP_KEY_NUM VRRP_STATS_KEY_UNKNOWN

const char *const vrrp_stats_keys[VRRP_KEY_NUM] = {
   [VRRP_STATS_KEY_V3_TX] =                        "vrrpv3_advertisement_tx",
   [VRRP_STATS_KEY_V3_RX] =                        "vrrpv3_advertisement_rx",
   [VRRP_STATS_KEY_V2_TX] =                        "vrrpv2_advertisement_tx",
   [VRRP_STATS_KEY_V2_RX] =                        "vrrpv2_advertisement_rx",
   [VRRP_STATS_KEY_ZERO_PRIORITY_RX] =             "zero_priority_rx",
   [VRRP_STATS_KEY_ZERO_PRIORITY_TX] =             "zero_priority_tx",
   [VRRP_STATS_KEY_V2_INCOMPATIBILITY] =           "vrrpv2_incompatibility",
   [VRRP_STATS_KEY_MISMATCHED_ADDR_LIST_PKTS] =    "mismatched_addr_list_pkts",
   [VRRP_STATS_KEY_MISMATCHED_AUTH_TYPE_PKTS] =    "mismatched_auth_type_pkts",
   [VRRP_STATS_KEY_IP_ADDRESS_OWNER_CONFLICTS] =   "ip_address_owner_conflicts",
   [VRRP_STATS_KEY_ADVERTISE_INTERVAL_ERRORS] =    "advertise_interval_errors",
   [VRRP_STATS_KEY_ADVERTISE_RECV_IN_INIT_STATE] = "advertise_recv_in_init_state",
   [VRRP_STATS_KEY_INVALID_GROUP] =                "invalid_group",
   [VRRP_STATS_KEY_OTHER_REASONS] =                "other_reasons",
   [VRRP_STATS_KEY_NEAR_FAILOVERS] =               "near_failovers",
   [VRRP_STATS_KEY_INIT_TO_MASTER] =               "init_to_master",
   [VRRP_STATS_KEY_INIT_TO_BACKUP] =               "init_to_backup",
   [VRRP_STATS_KEY_BACKUP_TO_MASTER] =             "backup_to_master",
   [VRRP_STATS_KEY_MASTER_TO_BACKUP] =             "master_to_backup",
   [VRRP_STATS_KEY_MASTER_TO_INIT] =               "master_to_init",
   [VRRP_STATS_KEY_BACKUP_TO_INIT] =               "backup_to_init"
};
