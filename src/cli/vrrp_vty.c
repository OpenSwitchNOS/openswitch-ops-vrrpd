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
 * File: vrrp_vty.c
 *
 * Purpose:  To add VRRP CLI configuration and display commands.
 */

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <pwd.h>

#include <readline/readline.h>
#include <readline/history.h>
#include <netinet/ether.h>

#include "getopt.h"
#include "vtysh/lib/version.h"
#include "vtysh/command.h"
#include "vtysh/memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "openswitch-dflt.h"
#include "vrrp_pub.h"
#include "vrrp_ip.h"


extern struct ovsdb_idl *idl;
int vrrp_max_vrs_per_router = 0;

VLOG_DEFINE_THIS_MODULE(vtysh_vrrpp_cli);

static struct cmd_node vrrp_if_node =
{
  VRRP_IF_NODE,
  "%s(config-if-vrrp)# "
};



/**PROC+**********************************************************************
 * Name:      vrrp_get_port_name_from_vr_ctxt_name
 *
 * Purpose:   VRRP CLI util routine to fetch port name from vrrp group context
 *            string.
 *
 * Params:    vr_ctxt_name - Pointer to context string
 *            port_name  -  buffer to copy port name value
 * Returns:   0 on success, -1 otherwise.
 **PROC-**********************************************************************/
int vrrp_get_port_name_from_vr_ctxt_name(const char *vr_ctxt_name,
                                         char *port_name)
{
   char *vr_ctxt_name_dup = NULL;
   char *p = NULL;

   /*
    * Make a copy of the vr context group.
    */
   vr_ctxt_name_dup = xstrdup(vr_ctxt_name);

   /* Extract the port name from vr group context, i.e, get the pointer to first
    * '.' location in the context string  "portName.vrid.addrFamily',
    * and replace the '.' with '/0'.
    */
   if ((p = strchr(vr_ctxt_name_dup, '.')))
   {
      *p = '\0';
   }
   else
   {
      VLOG_ERR("%s: Failed to extract port name from vr group context %s",
               __func__, vr_ctxt_name);
      return -1;
   }

   strcpy(port_name, vr_ctxt_name_dup);
   return 0;
}

/**PROC+**********************************************************************
 * Name:      vrrp_get_vrid_from_vr_ctxt_name
 *
 * Purpose:   VRRP CLI util routine to fetch vrid from vrrp group context string.
 *
 * Params:    vr_ctxt_name - Pointer to context string
 *
 * Returns:   valid vrid on success, -1 otherwise.
 **PROC-**********************************************************************/
int vrrp_get_vrid_from_vr_ctxt_name(const char *vr_ctxt_name)
{
   char *vr_ctxt_name_dup1 = NULL;
   char *vr_ctxt_name_dup2 = NULL;
   char *port_name_end = NULL;
   char *vr_name_end = NULL;

   /*
    * Make a copy of the vr context group.
    */
   vr_ctxt_name_dup1 = xstrdup(vr_ctxt_name);

   /* Extract the port name from vr group context, i.e, get the pointer to
    * first '.' location in the context string  "portName.vrid.addrFamily',
    * and copy rest of the string starting from 'first '.' + 1' to vr_ctxt_dup2.
    */
   if ((port_name_end = strchr(vr_ctxt_name_dup1, '.')))
   {
      port_name_end++;
      vr_ctxt_name_dup2 = xstrdup(port_name_end);
   }
   else
   {
      VLOG_ERR("%s: Failed to extract port name from vr group context %s",
               __func__, vr_ctxt_name);
      return -1;
   }

   /* Extract the vr name from vr_ctxt_dup2 string. i.e, get the pointer to
    * first '.' location in the string  "vrid.addrFamily',
    * and replace the '.' with '/0'.
    */
   if ((vr_name_end = strchr(vr_ctxt_name_dup2, '.')))
   {
      *vr_name_end = '\0';
   }
   else
   {
      VLOG_ERR("%s: Failed to extract vr name from vr group context %s",
               __func__, vr_ctxt_name);
      return -1;
   }

   return atoi(vr_ctxt_name_dup2);
}

/**PROC+**********************************************************************
 * Name:      vrrp_get_addr_family_from_vr_ctxt_name
 *
 * Purpose:   VRRP CLI util routine to fetch address family from vrrp group
 *            context string.
 *
 * Params:    vr_ctxt_name - Pointer to context string
 *
 * Returns:   o on success, -1 otherwise.
 **PROC-**********************************************************************/
int vrrp_get_addr_family_from_vr_ctxt_name(const char *vr_ctxt_name,
                                           char *addr_family)
{
   char *vr_ctxt_name_dup1 = NULL;
   char *vr_ctxt_name_dup2 = NULL;
   char *port_name_end = NULL;
   char *vr_name_end = NULL;

   /*
    * Make a copy of the vr context group.
    */
   vr_ctxt_name_dup1 = xstrdup(vr_ctxt_name);

   /* Get the pointer to end of port name, i.e first '.' location in the
    * context string., and copy rest of the string starting from 'first
    * '.' + 1 to vr_ctxt_dup2.
    */
   if ((port_name_end = strchr(vr_ctxt_name_dup1, '.')))
   {
      port_name_end++;
      vr_ctxt_name_dup2 = xstrdup(port_name_end);
   }
   else
   {
      VLOG_DBG("%s: Failed to get the pointer to first '.' location in the"
               "vr group context string %s",
               __func__, vr_ctxt_name);
      return -1;
   }

   /* Get the pointer to first '.' location in the vr_ctxt_dup2 string.
    * i.e, to the end of vrName in the string "vrid.addrFamily',
    * and copy rest of the string starting from 'first '.' + 1 to
    * addr_family.
    */

   if ((vr_name_end = strchr(vr_ctxt_name_dup2, '.')))
   {
      vr_name_end++;
      strcpy(addr_family, vr_name_end);
   }
   else
   {
      VLOG_ERR("%s: Failed to extract address family from vr group context %s",
               __func__, vr_ctxt_name);
      return -1;
   }

   return 0;
}

/**PROC+**********************************************************************
 * Name:      vrrp_ovsrec_insert_ip4_vr_to_port
 *
 * Purpose:   VRRP CLI routine to insert a new IPv4 virtual router value in
 *            port table 'virtual_ip4_routers' column
 *
 * Params:    port_row - Pointer to a row in port table
 *            vrrp_row - vrrp row value that to be inserted in
 *                       port's virtual_ip4_routers column
 *            vrid     - virtual router id
 *
 * Returns:   NONE.
 **PROC-**********************************************************************/
void
vrrp_ovsrec_insert_ip4_vr_to_port(const struct ovsrec_port *port_row,
                                  const struct ovsrec_vrrp *vrrp_row,
                                  int64_t vrid)
{
   int64_t *vrid_list = NULL;
   struct ovsrec_vrrp **vr_list = NULL;
   int i = 0;

   /* Insert VRRP virtual router table reference in Port table. */
   vrid_list = xmalloc(sizeof(int64_t) * (port_row->n_virtual_ip4_routers + 1));
   if (vrid_list == NULL)
   {
      VLOG_ERR("%s:malloc failed", __func__);
      return;
   }
   vr_list = xmalloc(sizeof * port_row->key_virtual_ip4_routers *
                           (port_row->n_virtual_ip4_routers + 1));
   if (vr_list == NULL)
   {
      VLOG_ERR("%s:malloc failed", __func__);
      return;
   }

   for (i = 0; i < port_row->n_virtual_ip4_routers; i++)
   {
      vrid_list[i] = port_row->key_virtual_ip4_routers[i];
      vr_list[i] = port_row->value_virtual_ip4_routers[i];
   }

   vrid_list[port_row->n_virtual_ip4_routers] = vrid;
   vr_list[port_row->n_virtual_ip4_routers] =
                     CONST_CAST(struct ovsrec_vrrp *, vrrp_row);

   ovsrec_port_set_virtual_ip4_routers(port_row, vrid_list, vr_list,
                                     port_row->n_virtual_ip4_routers + 1);
   free(vrid_list);
   free(vr_list);
}

/**PROC+**********************************************************************
 * Name:      vrrp_get_ovsrec_port_with_name
 *
 * Purpose:   VRRP CLI routine to find the port with matching name
 *
 * Params:    name - port name
 *
 * Returns:   valid port_row on success, NULL otherwise.
 **PROC-**********************************************************************/
static const struct ovsrec_port *
vrrp_get_ovsrec_port_with_name(const char *name)
{
   const struct ovsrec_port *port_row = NULL;

   /* Check if the VR is present or not. */
   OVSREC_PORT_FOR_EACH(port_row, idl)
   {
      if (strcmp(port_row->name, name) == 0)
      {
         return port_row;
      }
   }
   return NULL;
}

/**PROC+**********************************************************************
 * Name:     vrrp_ addr_family_str_to_inet_type
 *
 * Purpose:  VRRP CLI util routine to convert address family string to inettype
 *
 * Params:   addr_family - pointer to address family string
 *
 * Returns:   valid inetType on success, unknownType otherwise
 *
 **PROC-**********************************************************************/
InetAddressType
vrrp_addr_family_str_to_inet_type(const char *addr_family)
{
   if (strcmp(addr_family, "ipv4") == 0)
   {
      return ipv4Type;
   }

   if (strcmp(addr_family, "IPv4") == 0)
   {
      return ipv4Type;
   }

   if (strcmp(addr_family, "ipv6") == 0)
   {
      return ipv6Type;
   }

   if (strcmp(addr_family, "IPv6") == 0)
   {
      return ipv6Type;
   }
   return unknownType;
}

/**PROC+**********************************************************************
 * Name:      vrrp_get_ovsrec_ip4_vr_with_id
 *
 * Purpose:   VRRP CLI routine to find the ipv4 virtual router entry with
 *            matching vrid
 *
 * Params:    port_row - pointer to a row in port table
 *            vrid - virtual router id
 *
 * Returns:   valid vr row pointer on success, NULL otherwise.
 **PROC-**********************************************************************/
static const struct ovsrec_vrrp *
vrrp_get_ovsrec_ip4_vr_with_id(const struct ovsrec_port *port_row,
                               int vrid)
{
   int i = 0;

   for (i = 0; i < port_row->n_virtual_ip4_routers; i++)
   {
      if (port_row->key_virtual_ip4_routers[i] == vrid)
      {
         return port_row->value_virtual_ip4_routers[i];
      }
   }
   return NULL;
}

/**PROC+**********************************************************************
 * Name:      vrrp_get_ovsrec_ip6_vr_with_id
 *
 * Purpose:   VRRP CLI routine to find the ipv6 virtual router entry with
 *            matching vrid
 *
 * Params:    port_row - pointer to a row in port table
 *            vrid - virtual router id
 *
 * Returns:   valid vr row pointer on success, NULL otherwise.
 **PROC-**********************************************************************/
static const struct ovsrec_vrrp *
vrrp_get_ovsrec_ip6_vr_with_id(const struct ovsrec_port *port_row,
                               int vrid)
{
   int i = 0;

   for (i = 0; i < port_row->n_virtual_ip6_routers; i++)
   {
      if (port_row->key_virtual_ip6_routers[i] == vrid)
      {
         return port_row->value_virtual_ip6_routers[i];
      }
   }
   return NULL;
}

/**PROC+**********************************************************************
 * Name:      vrrp_ovsrec_set_defaults
 *
 * Purpose : Sets a vr row in db to default values
 *
 * Params:    vr_row - pointer to a row in VRRP table
 *            addr_family - IP address family
 *
 * Returns:   valid vr row pointer on success, NULL otherwise.
 **PROC-**********************************************************************/

void vrrp_ovsrec_set_defaults(const struct ovsrec_vrrp *vr_row,
                              const char *addr_family)
{
   InetAddressType inet_type;
   int64_t vrrp_version2 = VRRP_VERSION_2;
   int64_t vrrp_version3 = VRRP_VERSION_3;
   char *keys[2];
   int64_t int_values[2];
   bool preempt_disable = false;
   bool failback_enable = false;
   bool admin_enable = false;


   if (vr_row == NULL)
   {
      return;
   }

   inet_type = vrrp_addr_family_str_to_inet_type(addr_family);

   if (inet_type == ipv4Type)
   {
      /* Set verstion to 2*/
      ovsrec_vrrp_set_version(vr_row, &vrrp_version2, 1);
   }
   else if (inet_type == ipv6Type)
   {
      /* Set verstion to 3*/
      ovsrec_vrrp_set_version(vr_row, &vrrp_version3, 1);
   }

   /* set timers.
    * set advertisement interval to 1 sec (1000 milliseconds), and
    * preempt_delay_time to 0 seconds
    */
   keys[0] = "advertise_interval";
   int_values[0] = 1000;
   keys[1] = "preempt_delay_time";
   int_values[1] = 1;
   ovsrec_vrrp_set_timers(vr_row, keys, int_values,
                           ARRAY_SIZE(int_values));

   /* Set preempt disable to false*/
   ovsrec_vrrp_set_preempt_disable(vr_row, &preempt_disable, 1);
   /* Set failover to disable */
   ovsrec_vrrp_set_failover(vr_row, OVSREC_VRRP_FAILOVER_DISABLE);
   /* set failback enable to false */
   ovsrec_vrrp_set_failback_enable(vr_row, &failback_enable, 1);
   /* set admin enable to false */
   ovsrec_vrrp_set_admin_enable(vr_row, &admin_enable, 1);
}

/**PROC+**********************************************************************
 * Name:      vrrp_cli_create_ip6_vr_group
 *
 * Purpose:   VRRP CLI routine to create a virtual router group
 *
 * Params:    port_name - port name to which vr to be associated
 *            vrid - virtual router id
 *            addr_family - IP address family
 *
 * Returns:   CMD_SUCCESS on success, CMD_OVSDB_FAILURE otherwise.
 **PROC-**********************************************************************/
static int  vrrp_cli_create_ip6_vr_group(const char *port_name, int vrid,
                                         const char *addr_family)
{
   return CMD_SUCCESS;
}

/**PROC+**********************************************************************
 * Name:      vrrp_cli_create_ip4_vr_group
 *
 * Purpose:   VRRP CLI routine to create a virtual router group
 *
 * Params:    port_name - port name to which vr to be associated
 *            vrid - virtual router id
 *            addr_family - IP address family
 *
 * Returns:   CMD_SUCCESS on success, CMD_OVSDB_FAILURE otherwise.
 **PROC-**********************************************************************/
static int  vrrp_cli_create_ip4_vr_group(const char *port_name, int vrid,
                                         const char *addr_family)
{
   struct ovsdb_idl_txn* txn = NULL;
   enum ovsdb_idl_txn_status status;
   static char vr_name[VRRP_MAX_PORT_NAME_LENGTH]={0};
   const struct ovsrec_vrrp *vr_row = NULL;
   const struct ovsrec_port *port_row = NULL;

   snprintf(vr_name, VRRP_MAX_PORT_NAME_LENGTH, "%s.%d.%s", port_name, vrid,
            addr_family);

   txn = cli_do_config_start();
   if (txn == NULL)
   {
      VLOG_DBG("Transaction creation failed by %s. Function=%s, Line=%d",
             " cli_do_config_start()", __func__, __LINE__);
      cli_do_config_abort(txn);
      return CMD_OVSDB_FAILURE;
   }

   /* Check if the port is present or not. */
   port_row = vrrp_get_ovsrec_port_with_name(port_name);

   if(port_row == NULL)
   {
      cli_do_config_abort(txn);
      return CMD_SUCCESS;
   }

   if (!check_port_in_vrf(port_name))
   {
      vty_out (vty, "Interface %s is not L3.%s", port_name, VTY_NEWLINE);
      VLOG_DBG ("%s Interface \"%s\" is not attached to any VRF. "
                "It is attached to default bridge",
                __func__, port_name);
      cli_do_config_abort(txn);
      return CMD_SUCCESS;
   }

   /* Port found. See if the VR is already exist */
   vr_row = vrrp_get_ovsrec_ip4_vr_with_id(port_row, vrid);
   if (vr_row)
   {
      vty->node = VRRP_IF_NODE;
      vty->index = vr_name;
      cli_do_config_abort(txn);
      return CMD_SUCCESS;
   }

   /* If the row doesn't exist, create new one if maximim limits are not
    * reached
    */

   /* Check max VRs Per Router limit */
   if(vrrp_max_vrs_per_router == VRRP_MAX_VRS_PER_RTR)
   {
      vty_out(vty, "Cannot create VR."
              "Maximum number of VRs has already been reached on the router.%s",
            VTY_NEWLINE);
      cli_do_config_abort(txn);
      return CMD_SUCCESS;
   }

   /* Check max VRs Per Router limit */
   if((port_row->n_virtual_ip4_routers + port_row->n_virtual_ip6_routers)
       >= VRRP_MAX_VRS_PER_IFACE)
   {
      vty_out(vty,
           "Maximum number of VRs has already been reached on the interface.%s",
              VTY_NEWLINE);
      cli_do_config_abort(txn);
      return CMD_SUCCESS;
   }


   vr_row = ovsrec_vrrp_insert(txn);

   if (vr_row == NULL)
   {
      VLOG_DBG("Row insertion failed by %s. Function=%s, Line=%d",
               "ovsrec_vrrp_insert", __func__, __LINE__);
      cli_do_config_abort(txn);
      return CMD_OVSDB_FAILURE;
   }

   vrrp_ovsrec_insert_ip4_vr_to_port(port_row, vr_row, vrid);
   vrrp_ovsrec_set_defaults(vr_row, addr_family);

   status = cli_do_config_finish(txn);
   if(status == TXN_SUCCESS || status == TXN_UNCHANGED)
   {
      vrrp_max_vrs_per_router++;
      vty->node = VRRP_IF_NODE;
      vty->index = vr_name;
      return CMD_SUCCESS;
   }
   else
   {
      VLOG_ERR("Transaction commit failed in function=%s, line=%d",__func__,__LINE__);
      return CMD_OVSDB_FAILURE;
   }
}

DEFUN (cli_vrrp_create_vr_group,
       cli_vrrp_create_vr_group_cmd,
       "vrrp <1-255> address-family (ipv4 | ipv6)",
       "Creates a virtual router group\n"
       "Creates a virtual router group, the range is 1-255\n"
       "IP address family\n"
       "IPv4\n"
       "IPv6\n")

{
   InetAddressType inet_type;

   inet_type = vrrp_addr_family_str_to_inet_type(argv[1]);

   if (inet_type == ipv4Type)
   {
      return vrrp_cli_create_ip4_vr_group((char *)vty->index,
                                          atoi(argv[0]), argv[1]);
   }
   else if (inet_type == ipv6Type)
   {
      return vrrp_cli_create_ip6_vr_group((char *)vty->index,
                                          atoi(argv[0]), argv[1]);
   }
   else
   {
      vty_out(vty, "The address family value is invalid. "
              "The valid values are ipv4 or ipv6 %s", VTY_NEWLINE);
      return CMD_SUCCESS;
   }
}

/****************************************************************************
 * Function: vrrp_get_ip_prefix
 *
 * Extracts prefixlen and mask from ip address 'A.B.C.D/X'
 *
 * Parameters:  family - IP address family
 *              ip_address - pointer to ip adddress
 *              prefix[out] - buffer to store extracted prefix
 *              prefixlen[out] - buffer to store prefix len
 * Returns:
 *  return ipv4/ipv6 prefix and prefix length
 ****************************************************************************/
static int vrrp_get_ip_prefix(int family, char *ip_address, void *prefix,
                              unsigned char *prefixlen)
{
    char *p;
    char *ip_address_copy;
    int maxlen = (family == AF_INET) ? VRRP_IPV4_MAX_LEN :
                                       VRRP_IPV6_MAX_LEN;
    *prefixlen = maxlen;

    /*
     * Make a copy of the IP/IPv6 address.
     */
    ip_address_copy = xstrdup(ip_address);

    /*
     * Extract the mask length of the address.
     */
    if ((p = strchr(ip_address_copy, '/'))) {
        *p++ = '\0';
        *prefixlen = atoi(p);
    }

    /*
     * If the extracted mask length is greater
     * than 'maxlen', then free the memory in
     * 'ip_address_copy' and return -1.
     */
    if (*prefixlen > maxlen) {
        VLOG_DBG("Bad prefixlen %d > %d", *prefixlen, maxlen);
        free(ip_address_copy);
        return -1;
    }

    /*
     * If the extraction of the prefix fails, then
     * free the memory in 'ip_address_copy' and return -1.
     */
    if (inet_pton(family, ip_address_copy, prefix) == 0) {
        VLOG_DBG("%d inet_pton failed with %s", family, strerror(errno));
        free(ip_address_copy);
        return -1;
    }

    /*
     * In case of successful extraction,
     * free the memory in 'ip_address_copy'
     * and return 0.
     */
    free(ip_address_copy);
    return 0;
}

/****************************************************************************
 * Function: vrrp_iputil_ipv4_to_sockaddr
 *
 *  Creates a sockaddr_storage_t from an in_addr ipv4 address
 *
 * Parameters:
 *    ipaddr   [in]      - the ipv4 address
 *   SOCKADDR_STORAGE_T* [in/out]  - the sock addr struct into which to put the ipv4 in_addr
 *
 * Returns:
 *  sockaddr_storage_t* - the sa that was passed in
 *
 ****************************************************************************/
SOCKADDR_STORAGE_T* vrrp_iputil_ipv4_to_sockaddr(struct in_addr *ipaddr,
                                                 SOCKADDR_STORAGE_T* sin)
{
   if (sin == NULL) {
      return NULL;
   }

   memset(sin, 0, sizeof(struct sockaddr_in));
   sin->ipv4.sin_family = AF_INET;
   sin->ipv4.sin_addr.s_addr = htonl(ipaddr->s_addr);

   return (SOCKADDR_STORAGE_T*)sin;
}

/*****************************************************************************
 * Function:    vrrp_iputil_prefixlen_to_sockaddr
 *
 *  Provide a utility function to perform a conversion from
 *          a prefix length to a sockaddr.
 *
 * Parameters:
 *     ss - The sockaddr to convert from
 *          return() - The prefix length
 *
 * Retruns:
 *  The prefix length
 *
 *****************************************************************************/
bool vrrp_iputil_prefixlen_to_sockaddr(int addrFamily, uint8_t prefixLen,
                                              SOCKADDR_STORAGE_T *ss)
{
   int i, len = 0;
   IP_ADDRESS mask;

   if (ss == NULL)
   {
      return 0;
   }

   if (addrFamily == AF_INET)
   {
      mask = IP_PREFIXLEN_TO_MASK(prefixLen);
      memset(ss, 0, sizeof(struct sockaddr_in));
      ss->ipv4.sin_family = AF_INET;
      ss->ipv4.sin_addr.s_addr = mask;
   }
   else if (addrFamily == AF_INET6)
   {
      /* Convert to a prefix length, one 32-bit section at a time */
      len = prefixLen;
      for (i = 0; i < 4; i++)
      {
         if (len >= 32) {
            ss->ipv6.sin6_addr.s6_addr32[i] = 0xFFFFFFFF;
            len -= 32;
         } else if (len > 0) {
            ss->ipv6.sin6_addr.s6_addr32[i] = IP_PREFIXLEN_TO_MASK(len);
            len = 0;
         } else {
            ss->ipv6.sin6_addr.s6_addr32[i] = 0;
         }
      }
   }
   else
   {
      assert(0);
   }

   return(len);
}

/*****************************************************************************
 * Function:    vrrp_iputil_mask_sockaddr
 *
 *  Provide a utility function to perform masking of one
 *          sockaddr with another sockaddr. The result is saved in
 *          a caller-provided third sockaddr.
 *          NOTE: It is possible that ip == maskedIp
 *
 * Parameters:
 *          ip - The sockaddr to use as a base
 *          mask - The sockaddr to mask with
 *          maskedIp - (OUT) The destination of the result
 *
 * Retruns:
 *  (none)
 *
 *****************************************************************************/

void vrrp_iputil_mask_sockaddr(const SOCKADDR_STORAGE_T *ip,
                               const SOCKADDR_STORAGE_T *mask,
                               SOCKADDR_STORAGE_T *maskedIp)
{
   int i;

   if (ip == NULL || mask == NULL || maskedIp == NULL || (mask == maskedIp))
   {
      return;
   }

   if (ip != maskedIp)
      vrrp_iputil_sockaddr_copy(ip, maskedIp);

   if (ip->ipv4.sin_family == AF_INET)
   {
      maskedIp->ipv4.sin_addr.s_addr &= mask->ipv4.sin_addr.s_addr;
   }
   else if (ip->ipv4.sin_family == AF_INET6)
   {
      /* Bitmask the address, one 32-bit section at a time */
      for (i = 0; i < 16; i++)
      {
         maskedIp->ipv6.sin6_addr.s6_addr[i] &=
             mask->ipv6.sin6_addr.s6_addr[i];
      }
   }
   else
   {
      return;
   }
}

/*****************************************************************************
 * Function:      vrrp_iputil_sockaddr_equal
 *
 *    Determine whether the given SOCKADDR_STORAGE_Ts are equal
 *
 * Parameters:
 *       ip1 - A pointer to the SOCKADDR_STORAGE_T
 *       ip2 - A pointer to the SOCKADDR_STORAGE_T
 *
 * Retruns:
 *    TRUE or FALSE
 *
 *****************************************************************************/

bool vrrp_iputil_sockaddr_equal(const SOCKADDR_STORAGE_T *ip1,
                                const SOCKADDR_STORAGE_T *ip2)
{
   if (ip1 == NULL || ip2 == NULL)
   {
      return false;
   }

   if ( (ip1->ss_family == AF_INET) && (ip2->ss_family == AF_INET))
   {
      return( memcmp(&ip1->ipv4.sin_addr, &ip2->ipv4.sin_addr,
                     sizeof(ip1->ipv4.sin_addr)) == 0 );
   }
   else if ( (ip1->ss_family == AF_INET6) && (ip2->ss_family == AF_INET6))
   {
      return( memcmp(&ip1->ipv6.sin6_addr, &ip2->ipv6.sin6_addr,
                     sizeof(ip1->ipv6.sin6_addr)) == 0 );
   }

   return false;
}

/*****************************************************************************
 * Function:      vrrp_iputil_sockaddr_copy
 *
 *    Copy the contents of the source sockaddr into the contents
 *            of the destination sockaddr.
 *
 * Parameters:
 *       src - A pointer to the SOCKADDR_STORAGE_T to copy FROM
 *            dst - A pointer to the SOCKADDR_STORAGE_T to copy TO
 *
 * Retruns:
 *
 * Notes: We only copy data from the src up through the sin_len value.  In
 *        the case of ipv4, this means the entire 28 bytes will not overwrite
 *        the dst, but will instead copy just 16 bytes from the src.  The caller
 *        should be aware of this and not expect this function to overwrite
 *        these bytes in the dst, and if they rely on these bytes being set to
 *        0, they should zero out the entire sockaddr dst before calling this
 *        function.
 *
 *****************************************************************************/

void vrrp_iputil_sockaddr_copy(const SOCKADDR_STORAGE_T *src,
                                       SOCKADDR_STORAGE_T *dst)
{
   if (src == NULL || dst == NULL)
   {
      return;
   }

   memcpy(dst, src, sizeof(SOCKADDR_STORAGE_T));
}
/**PROC+**********************************************************************
 * Name:      vrrp_check_ip4_vr_address_duplicate
 *
 * Purpose:   In db, search for the VR entry associated with given
 *            port's IP address.
 *
 * Params:    port_row     -> pointer to a port row in port table
 *            ip_addr -> IP address in question
 *
 * Returns:   Virtual Router ID if found, '0' (invalid VRID) otherwise
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
uint8_t
vrrp_check_ip4_vr_address_duplicate(const struct ovsrec_port *port_row,
                                    const char * ip_addr)
{
   const struct ovsrec_vrrp *vr_row = NULL;
   const char *cfg_ip = NULL;
   int i;
   int j;

   if (port_row == NULL)
   {
      return 0;
   }

   for (i = 0; i < port_row->n_virtual_ip4_routers; i++)
   {
      vr_row = port_row->value_virtual_ip4_routers[i];
      cfg_ip = smap_get(&vr_row->ip_address, OVSREC_VRRP_IP_ADDRESS_PRIMARY);

      if (cfg_ip && !strcmp(cfg_ip, ip_addr))
      {
         return port_row->key_virtual_ip4_routers[i];
      }

      for (j = 0; j < vr_row->n_ip_address_secondary; j++)
      {
         if (!strcmp (vr_row->ip_address_secondary[j], ip_addr))
         {
           return port_row->key_virtual_ip4_routers[i];
         }
      }
   }

   return 0;
}

/**PROC+**********************************************************************
 * Name:      vrrp_check_ip6_vr_address_duplicate
 *
 * Purpose:   In config, search for the VR entry associated with given
 *            port's IP address.
 *
 * Params:    port_row     -> pointer to a port row in port table
 *            ip_addr -> IP address in question
 *
 * Returns:   Virtual Router ID if found, '0' (invalid VRID) otherwise
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
uint8_t
vrrp_check_ip6_vr_address_duplicate(const struct ovsrec_port *port_row,
                                    char * ip_addr)
{
   const struct ovsrec_vrrp *vr_row = NULL;
   const char *cfg_ip = NULL;
   int i;
   int j;

   if (port_row == NULL)
   {
      return 0;
   }

   for (i = 0; i < port_row->n_virtual_ip6_routers; i++)
   {
      vr_row = port_row->value_virtual_ip6_routers[i];
      cfg_ip = smap_get(&vr_row->ip_address, OVSREC_VRRP_IP_ADDRESS_PRIMARY);

      if (!strcmp(cfg_ip, ip_addr))
      {
         return port_row->key_virtual_ip6_routers[i];
      }

      for (j = 0; j < vr_row->n_ip_address_secondary; j++)
      {
         if (!strcmp (vr_row->ip_address_secondary[j], ip_addr))
         {
           return port_row->key_virtual_ip6_routers[i];
         }
      }
   }
   return 0;
}

/**PROC+**********************************************************************
 * Name:      vrrp_check_ip_addr_or_subnet_matches
 *
 * Purpose:   Check if IP configuration of the port matches to the requested
 *            search patterns. This function checks either for the matching
 *            subnet existence or for the existence of the particular IP
 *            address (and 'ip_mask' if it is not zero).
 *
 * Params:    addr1 -address to be matched against
 *            addr2 - address to match
 *            prefix_len - prefix length of addr1
 *
 *
 * Returns:   TRUE if matching IP configuration is found on the port,
 *            FALSE otherwise
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/

bool
vrrp_check_ip_addr_or_subnet_matches (struct in_addr *addr1,
                                      struct in_addr *addr2,
                                      uint8_t prefix_len)
{
   SOCKADDR_STORAGE_T  sock_ip_addr1;
   SOCKADDR_STORAGE_T  sock_ip_addr2;
   SOCKADDR_STORAGE_T  subnetMask;
   SOCKADDR_STORAGE_T  masked_ip_addr1;
   SOCKADDR_STORAGE_T  masked_ip_addr2;
   int retVal;

   memset(&sock_ip_addr1, 0, sizeof(SOCKADDR_STORAGE_T));
   memset(&sock_ip_addr2, 0, sizeof(SOCKADDR_STORAGE_T));
   memset(&subnetMask, 0, sizeof(SOCKADDR_STORAGE_T));
   memset(&masked_ip_addr1, 0, sizeof(SOCKADDR_STORAGE_T));
   memset(&masked_ip_addr2, 0, sizeof(SOCKADDR_STORAGE_T));


   /* Change the IP address to sockaddr form, and comapre the
    * masked IP to get the matched subnet interface address
    */
   vrrp_iputil_ipv4_to_sockaddr(addr1, &sock_ip_addr1);
   vrrp_iputil_ipv4_to_sockaddr(addr2, &sock_ip_addr2);
   vrrp_iputil_prefixlen_to_sockaddr(AF_INET, prefix_len, &subnetMask);
   vrrp_iputil_mask_sockaddr(&sock_ip_addr1, &subnetMask, &masked_ip_addr1);
   vrrp_iputil_mask_sockaddr(&sock_ip_addr2, &subnetMask, &masked_ip_addr2);

   if ((retVal = vrrp_iputil_sockaddr_equal(&masked_ip_addr1, &masked_ip_addr2)))
   {
      return true;
   }
   return false;
}

/**PROC+**********************************************************************
 * Name:      vrrp_port_has_subnet_or_ip_address
 *
 * Purpose:   Check if IP configuration of the port matches to the requested
 *            search patterns. This function checks either for the matching
 *            subnet existence or for the existence of the particular IP
 *            address (and 'ip_mask' if it is not zero).
 *
 * Params:    port_row          -> pointer to a port row in port table
 *            match_ip_addr           -> IP address to match
 *            ip_mask      -> IP address mask
 *            check_subnet -> boolean that indicates what kind of check
 *                            to perform, if 'TRUE' then check for subnet,
 *                            otherwise do check for the IP address
 *
 * Returns:   TRUE if matching IP configuration is found on the port,
 *            FALSE otherwise
 *
 * Globals:   none
 *
 **PROC-**********************************************************************/
bool
vrrp_port_has_subnet_or_ip_address(const struct ovsrec_port *port_row,
                                   const char *vr_ip_addr,
                                   bool check_subnet)
{
   struct in_addr if_ip_in_addr;
   struct in_addr vr_ip_in_addr;
   struct prefix_ipv4 v4_prefix;
   char *if_ip_addr = NULL;
   char *p = NULL;
   int res = false;
   int i;


   if (port_row == NULL || vr_ip_addr == NULL)
   {
      return res;
   }

   /* convert the vip_addr to binary form */
   inet_pton(AF_INET, vr_ip_addr, &vr_ip_in_addr);

   if(port_row->ip4_address)
   {
      if_ip_addr = xstrdup(port_row->ip4_address);

      /* Extract the ip address..i.e, first, get the pointer to '/' location
       * in the ip addr a.b.c.d/24', and replace the '/' with '/0'.
       */
      if ((p = strchr(if_ip_addr, '/')))
      {
        *p = '\0';
      }
      /* Now, convert the string to binary form */
      inet_pton(AF_INET, if_ip_addr, &if_ip_in_addr);

      /* Get the if ip prefix len*/
      res = vrrp_get_ip_prefix(AF_INET, port_row->ip4_address,
                                  &v4_prefix.prefix, &v4_prefix.prefixlen);
      if (res)
      {
          VLOG_ERR("%s: Error converting DB string to prefix: %s",
                    __func__, port_row->ip4_address);
          return false;
      }

      res = vrrp_check_ip_addr_or_subnet_matches(&if_ip_in_addr, &vr_ip_in_addr,
                                                 v4_prefix.prefixlen);
   }

   if (!res)
   {
      for (i = 0; i < port_row->n_ip4_address_secondary; i++)
      {
         if_ip_addr = xstrdup(port_row->ip4_address_secondary[i]);
         /* Extract the ip address..i.e, first, get the pointer to '/' location
          * in the ip addr a.b.c.d/24', and replace the '/' with '/0'.
          */
         if ((p = strchr(if_ip_addr, '/')))
         {
           *p = '\0';
         }
         /* Now, convert the string to binary form */
         inet_pton(AF_INET, if_ip_addr, &if_ip_in_addr);

         /* Get the if ip prefix len*/
         res = vrrp_get_ip_prefix(AF_INET, port_row->ip4_address_secondary[i],
                                  &v4_prefix.prefix, &v4_prefix.prefixlen);
         if (res)
         {
             VLOG_ERR("%s: Error converting DB string to prefix: %s",
                       __func__, port_row->ip4_address);
             return false;
         }

         res = vrrp_check_ip_addr_or_subnet_matches(&if_ip_in_addr, &vr_ip_in_addr,
                                                    v4_prefix.prefixlen);
         if (res)
         {
            /* match found. done*/
            break;
         }
      }
   }

   if (!check_subnet && if_ip_addr)
   {
      res = !strcmp(if_ip_addr, vr_ip_addr);
   }

   return res;
}
/**PROC+**********************************************************************
 * Name:     vrrp_configure_ip_addr
 *
 * Purpose:  VRRP CLI util routine to add virtual IP address to a group in DB.
 *
 * Params:   vr_row - pointer to a row in VRRP table
 *           ip_addr - pointer to IP address to be added
 *
 * Returns:   none
 *
 **PROC-**********************************************************************/
void vrrp_configure_ip_addr(const struct ovsrec_vrrp *vr_row,
                            const char *ip_addr, int vrid, bool secondary)
{
   struct smap smap;
   char **secondary_ip_addresses = NULL;
   size_t i;

   VLOG_DBG("%s: Configuring IP address to vr :%d",__func__, vrid);

   if (secondary)
   {
      secondary_ip_addresses = xmalloc(VR_IP_ADDRESS_LENGTH *
                                       (vr_row->n_ip_address_secondary + 1));
      if (secondary_ip_addresses == NULL)
      {
         return;
      }

      for (i = 0; i < vr_row->n_ip_address_secondary; i++)
      {
         secondary_ip_addresses[i] = vr_row->ip_address_secondary[i];
      }

      secondary_ip_addresses[vr_row->n_ip_address_secondary] = (char *)ip_addr;

      ovsrec_vrrp_set_ip_address_secondary(vr_row, secondary_ip_addresses,
                                           vr_row->n_ip_address_secondary + 1);

      free (secondary_ip_addresses);
   }
   else
   {
      smap_init(&smap);
      smap_clone(&smap, &vr_row->ip_address);
      smap_replace(&smap, OVSREC_VRRP_IP_ADDRESS_PRIMARY, ip_addr);

      VLOG_DBG("updating vr :%d primary IP address\n", vrid);

      ovsrec_vrrp_set_ip_address(vr_row, &smap);

      smap_destroy(&smap);

      VLOG_DBG ("%s The command succeeded and vr interface %d was configured"
             " with IP address \"%s\"",
             __func__, vrid, ip_addr);
   }
}


/**PROC+**********************************************************************
 * Name:     vrrp_cli_add_ip
 *
 * Purpose:  VRRP CLI routine to add virtual IP address to a group
 *
 * Params:   addr_family - pointer to address family string
  *
 * Returns:   valid inetType on success, unknownType otherwise
 *
 **PROC-**********************************************************************/
static int vrrp_cli_add_ip(const char *vr_ctxt_name, const char *ip_addr,
                           bool secondary)
{
   const struct ovsrec_vrrp *vr_row = NULL;
   const struct ovsrec_port *port_row = NULL;
   struct ovsdb_idl_txn *status_txn = NULL;
   enum ovsdb_idl_txn_status status;
   bool port_found = false;
   char port_name[VRRP_MAX_PORT_NAME_LENGTH] = {0};
   char addr_family[VRRP_MAX_ADDR_FAMILY_NAME_LENGTH] = {0};
   int vrid;
   int retval;
   InetAddressType inet_type;
   int64_t owner_priority = VRRP_OWNER_VR_PTY;
   int64_t backup_priority = VRRP_DEF_BACKUP_VR_PTY;

   retval = vrrp_get_port_name_from_vr_ctxt_name(vr_ctxt_name, port_name);
   if (retval != 0)
   {
      VLOG_DBG("%s: Failed to get port name", __func__);
      return CMD_SUCCESS;
   }

   vrid = vrrp_get_vrid_from_vr_ctxt_name(vr_ctxt_name);
   if (!IS_VALID_VRID(vrid))
   {
      VLOG_DBG("%s: invalid vrid", __func__);
      return CMD_SUCCESS;
   }

   retval = vrrp_get_addr_family_from_vr_ctxt_name(vr_ctxt_name, addr_family);
   if (retval != 0)
   {
      VLOG_DBG("%s: invalid address family", __func__);
      return CMD_SUCCESS;
   }

   inet_type = vrrp_addr_family_str_to_inet_type(addr_family);

   status_txn = cli_do_config_start ();
   if (status_txn == NULL)
   {
      VLOG_ERR (OVSDB_TXN_CREATE_ERROR);
      cli_do_config_abort (status_txn);
      return CMD_OVSDB_FAILURE;
   }

   /* Check if the PORT is present or not. */
   OVSREC_PORT_FOR_EACH(port_row, idl)
   {
     if (strcmp(port_row->name, port_name) == 0)
     {
        port_found = true;
        break;
      }

   }

   if (port_found)
   {
      switch(inet_type)
      {
         case ipv4Type:
            /* Check in the config if IP address is already used by another VR
             * on the port
             */
            if ((retval = vrrp_check_ip4_vr_address_duplicate(port_row, ip_addr)))
            {
               vty_out(vty,
                      "Another VR (vrid %d) is already using this IP address\n",
                       retval);
               cli_do_config_abort (status_txn);
               return CMD_SUCCESS;
            }
            /* Get the vr_row value from the vrid */
            vr_row = vrrp_get_ovsrec_ip4_vr_with_id(port_row, vrid);
            if (!vr_row)
            {
               VLOG_DBG("%s: Failed to get vr row", __func__);
               cli_do_config_abort (status_txn);
               return CMD_SUCCESS;
            }
            /* Check if IP address is configured on the VR's port
             */
            if (vrrp_port_has_subnet_or_ip_address(port_row, ip_addr, false))
            {
               /* VR mode is owner, as VIP is same as one of the Interface IP.
                * Set default priority to Owner priority
                */
               ovsrec_vrrp_set_priority(vr_row, &owner_priority, 1);
            }
            /* Check if there is a matching IP subnet configured on the port*/
            else if (vrrp_port_has_subnet_or_ip_address(port_row, ip_addr, true))
            {
               /* VR mode is backup, set it to default backup prioirity
                */
               ovsrec_vrrp_set_priority(vr_row, &backup_priority, 1);
            }
            else
            {
               /* An attempt to associate non-existing IP address*/
               vty_out(vty,
                      "Specified IP address or subnet not found on the"
                      " interface\n");
               cli_do_config_abort (status_txn);
               return CMD_SUCCESS;
            }
            break;
         case ipv6Type:
            /* Port found. Get the vr_row value from the vrid */
            vr_row = vrrp_get_ovsrec_ip6_vr_with_id(port_row, vrid);
            if (!vr_row)
            {
               VLOG_DBG("%s: Failed to get vr row", __func__);
               cli_do_config_abort (status_txn);
               return CMD_SUCCESS;
            }
            break;
         default:
            return CMD_SUCCESS;
      }


      vrrp_configure_ip_addr(vr_row, ip_addr, vrid, secondary);

      status = cli_do_config_finish (status_txn);
      if (status == TXN_SUCCESS)
      {
         return CMD_SUCCESS;
      }
      else if (status == TXN_UNCHANGED)
      {
         return CMD_SUCCESS;
      }
      else
      {
         VLOG_ERR("Transaction commit failed in function=%s, line=%d",__func__,
                  __LINE__);
         return CMD_OVSDB_FAILURE;
      }
   }

   return CMD_SUCCESS;
}

DEFUN (cli_vrrp_add_ip,
       cli_vrrp_add_ip_cmd,
       "address A.B.C.D (primary | secondary)",
        IP_STR
        IP_STR
       "Primary Address\n"
       "Secondary Address\n")
{
   bool secondary = false;

   if (argv[1] != NULL)
   {
      if (strcmp(argv[1], "secondary") == 0)
      {
         secondary = true;
      }
   }

   return vrrp_cli_add_ip((char *)vty->index, argv[0], secondary);
}

DEFUN(cli_vrrp_version_func,
      cli_vrrp_version_cmd,
      "version <2-3>",
      "Configures the VRRP protocol version value\n"
      "Specifies the VRRP protocol version value\n")
{
   const struct ovsrec_vrrp *vr_row = NULL;
   const struct ovsrec_port *port_row = NULL;
   struct ovsdb_idl_txn *status_txn = NULL;
   enum ovsdb_idl_txn_status status;
   bool port_found = false;
   char port_name[VRRP_MAX_PORT_NAME_LENGTH] = {0};
   char addr_family[VRRP_MAX_ADDR_FAMILY_NAME_LENGTH] = {0};
   int vrid;
   int retval;
   InetAddressType inet_type;
   int64_t vr_version = (int64_t) atoi(argv[0]);
   int64_t vrrp_version2 = VRRP_VERSION_2;
   const char *vr_ctxt_name = (char *)vty->index;

   retval = vrrp_get_port_name_from_vr_ctxt_name(vr_ctxt_name, port_name);
   if (retval != 0)
   {
      VLOG_DBG("%s: Failed to get port name", __func__);
      return CMD_SUCCESS;
   }

   vrid = vrrp_get_vrid_from_vr_ctxt_name(vr_ctxt_name);
   if (!IS_VALID_VRID(vrid))
   {
      VLOG_DBG("%s: invalid vrid", __func__);
      return CMD_SUCCESS;
   }

   retval = vrrp_get_addr_family_from_vr_ctxt_name(vr_ctxt_name, addr_family);
   if (retval != 0)
   {
      VLOG_DBG("%s: invalid address family", __func__);
      return CMD_SUCCESS;
   }

   inet_type = vrrp_addr_family_str_to_inet_type(addr_family);

   status_txn = cli_do_config_start();

   if (status_txn == NULL)
   {
      VLOG_ERR (OVSDB_TXN_CREATE_ERROR);
      cli_do_config_abort (status_txn);
      return CMD_OVSDB_FAILURE;
   }

   /* Check if the PORT is present or not. */
   OVSREC_PORT_FOR_EACH(port_row, idl)
   {
     if (strcmp(port_row->name, port_name) == 0)
     {
        port_found = true;
        break;
      }

   }

   if (port_found)
   {
      /* Get the vr_row value from the vrid */
      vr_row = vrrp_get_ovsrec_ip4_vr_with_id(port_row, vrid);
      if (!vr_row)
      {
         VLOG_DBG("%s: Failed to get vr row", __func__);
         cli_do_config_abort (status_txn);
         return CMD_SUCCESS;
      }

      /* IPv6 VRs support only version 3 */
      if ( (inet_type == ipv6Type) && (vr_version == vrrp_version2))
      {
         vty_out(vty,
                "The value cannot be used for an IPv6 virtual router\n");
         VLOG_DBG("%s: The value cannot be used for an IPv6 virtual router", __func__);
         cli_do_config_abort (status_txn);
         return CMD_SUCCESS;
      }

      ovsrec_vrrp_set_version(vr_row, &vr_version, 1);

      status = cli_do_config_finish (status_txn);
      if (status == TXN_SUCCESS || status == TXN_UNCHANGED)
      {
         return CMD_SUCCESS;
      }
      else
      {
         VLOG_ERR("Transaction commit failed in function=%s, line=%d",__func__,
                  __LINE__);
         return CMD_OVSDB_FAILURE;
      }
   }
   else
   {
      VLOG_DBG("%s: PORT is not present", __func__);
      cli_do_config_abort (status_txn);
      return CMD_SUCCESS;
   }

   return CMD_SUCCESS;
}

DEFUN(cli_vrrp_no_version_func,
      cli_vrrp_no_version_cmd,
      "no version",
      NO_STR
      "Configures the VRRP protocol version value\\n")
{
   const struct ovsrec_vrrp *vr_row = NULL;
   const struct ovsrec_port *port_row = NULL;
   struct ovsdb_idl_txn *status_txn = NULL;
   enum ovsdb_idl_txn_status status;
   bool port_found = false;
   char port_name[VRRP_MAX_PORT_NAME_LENGTH] = {0};
   char addr_family[VRRP_MAX_ADDR_FAMILY_NAME_LENGTH] = {0};
   int vrid;
   int retval;
   InetAddressType inet_type;
   const char *vr_ctxt_name = (char *)vty->index;
   int64_t vrrp_version2 = VRRP_VERSION_2;
   int64_t vrrp_version3 = VRRP_VERSION_3;

   retval = vrrp_get_port_name_from_vr_ctxt_name(vr_ctxt_name, port_name);
   if (retval != 0)
   {
      VLOG_DBG("%s: Failed to get port name", __func__);
      return CMD_SUCCESS;
   }

   vrid = vrrp_get_vrid_from_vr_ctxt_name(vr_ctxt_name);
   if (!IS_VALID_VRID(vrid))
   {
      VLOG_DBG("%s: invalid vrid", __func__);
      return CMD_SUCCESS;
   }

   retval = vrrp_get_addr_family_from_vr_ctxt_name(vr_ctxt_name, addr_family);
   if (retval != 0)
   {
      VLOG_DBG("%s: invalid address family", __func__);
      return CMD_SUCCESS;
   }

   inet_type = vrrp_addr_family_str_to_inet_type(addr_family);

   status_txn = cli_do_config_start();

   if (status_txn == NULL)
   {
      VLOG_ERR (OVSDB_TXN_CREATE_ERROR);
      cli_do_config_abort (status_txn);
      return CMD_OVSDB_FAILURE;
   }

   /* Check if the PORT is present or not. */
   OVSREC_PORT_FOR_EACH(port_row, idl)
   {
     if (strcmp(port_row->name, port_name) == 0)
     {
        port_found = true;
        break;
      }

   }

   if (port_found)
   {
      /* Get the vr_row value from the vrid */
      vr_row = vrrp_get_ovsrec_ip4_vr_with_id(port_row, vrid);
      if (!vr_row)
      {
         VLOG_DBG("%s: Failed to get vr row", __func__);
         cli_do_config_abort (status_txn);
         return CMD_SUCCESS;
      }

      if (inet_type == ipv4Type)
      {
         /* Set verstion to 2*/
         ovsrec_vrrp_set_version(vr_row, &vrrp_version2, 1);
      }
      else if (inet_type == ipv6Type)
      {
         /* Set verstion to 3*/
         ovsrec_vrrp_set_version(vr_row, &vrrp_version3, 1);
      }

      status = cli_do_config_finish (status_txn);
      if (status == TXN_SUCCESS || status == TXN_UNCHANGED)
      {
         return CMD_SUCCESS;
      }
      else
      {
         VLOG_ERR("Transaction commit failed in function=%s, line=%d",__func__,
                  __LINE__);
         return CMD_OVSDB_FAILURE;
      }
   }
   else
   {
      VLOG_DBG("%s: PORT is not present", __func__);
      cli_do_config_abort (status_txn);
      return CMD_SUCCESS;
   }

   return CMD_SUCCESS;
}

DEFUN (cli_vrrp_exit_vrrp_if_mode,
       cli_vrrp_exit_vrrp_if_mode_cmd,
       "exit",
       "Exit current mode and down to previous mode\n")
{
   static char port_name[VRRP_MAX_PORT_NAME_LENGTH] = {0};
   int retval = 0;

   retval = vrrp_get_port_name_from_vr_ctxt_name(vty->index, port_name);
   if (retval != 0)
   {
      VLOG_DBG("%s: Failed to get port name", __func__);
   }

   vty->index = port_name;
   return vtysh_exit(vty);
}

/*
 * Function: vrrp_ovsdb_init
 * Responsibility : Add tables/columns needed for VRRP config commands.
 */
static void vrrp_ovsdb_init()
{
   ovsdb_idl_add_table(idl, &ovsrec_table_vrrp);
   ovsdb_idl_add_column(idl, &ovsrec_vrrp_col_ip_address);
   ovsdb_idl_add_column(idl, &ovsrec_vrrp_col_priority);
   ovsdb_idl_add_column(idl, &ovsrec_vrrp_col_admin_enable);
   ovsdb_idl_add_column(idl, &ovsrec_vrrp_col_failover);
   ovsdb_idl_add_column(idl, &ovsrec_vrrp_col_failback_enable);
   ovsdb_idl_add_column(idl, &ovsrec_port_col_virtual_ip4_routers);
   ovsdb_idl_add_column(idl, &ovsrec_port_col_virtual_ip6_routers);
   ovsdb_idl_add_column(idl, &ovsrec_vrrp_col_version);

   return;
}

/*
 * Function: cli_pre_init
 * Responsibility : Initialize VRRP cli node.
 */
void cli_pre_init(void)
{

  /* Install VRRP interface node*/
  install_node(&vrrp_if_node, NULL);
  vtysh_install_default(VRRP_IF_NODE);

  /* Add tables/columns needed for vrrp config commands. */
  vrrp_ovsdb_init();

}

/*
 * Function: cli_post_init
 * Responsibility: Initialize VRRP cli element.
 */
void cli_post_init(void)
{
   install_element(INTERFACE_NODE, &cli_vrrp_create_vr_group_cmd);
   install_element(VRRP_IF_NODE, &cli_vrrp_add_ip_cmd);
   install_element(VRRP_IF_NODE, &cli_vrrp_version_cmd);
   install_element(VRRP_IF_NODE, &cli_vrrp_no_version_cmd);
   install_element(VRRP_IF_NODE, &cli_vrrp_exit_vrrp_if_mode_cmd);
   return;
}
