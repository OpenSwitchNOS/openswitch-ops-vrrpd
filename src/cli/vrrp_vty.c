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


int vrrp_max_vrs_per_router = 0;

VLOG_DEFINE_THIS_MODULE(vtysh_vrrpp_cli);

static struct cmd_node vrrp_if_node =
{
  VRRP_IF_NODE,
  "%s(config-if-vrrp)# "
};


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

/*
 * Find the port with matching name.
 */
static const struct ovsrec_port *
vrrp_get_ovsrec_port_with_name(char *name)
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

/*
 * Find the VR with matching id.
 */
static const struct ovsrec_vrrp *
vrrp_get_ovsrec_ip4_vr_with_id(const struct ovsrec_port *port_row,
                               int vrid)
{
   int i = 0;

   for (i = 0; i < port_row->n_virtual_ip4_routers; i++)
   {
      if (port_row->key_virtual_ip4_routers[i] == vrid)
      {
         return port_row->value_bgp_routers[i];
      }
   }
   return NULL;
}

static int  vrrp_create_vr_group(const char *port_name, int vrid,
                                 const char *addr_family)
{
   struct ovsdb_idl_txn* txn = NULL;
   enum ovsdb_idl_txn_status status;
   static char vr_name[LAG_NAME_LENGTH]={0};
   bool vr_found = false;
   int if_index = 0;
   const struct ovsrec_vrrp *vr_row = NULL;
   const struct ovsrec_port *port_row = NULL;
   const struct ovsrec_port *port_tmp_row = NULL;
   struct ovsrec_vrrp **vrs = NULL;
   bool port_found = false;
   int i = 0;

   snprintf(vr_name, VRRP_VR_NAME_LENGTH, "%s.%s.%s", port_name, vrid,
            addr_family);

   /* Check if the port is present or not. */
   port_row = vrrp_get_ovsrec_port_with_name(port_name);

   if(port_row == NULL)
   {
      return CMD_SUCCESS;
   }

   /* Port found. See if the VR is already exist */
   vr_row = vrrp_get_ovsrec_ip4_vr_with_id(port_row, vrid);
   if (vr_row)
   {
      vty->node = VRRP_IF_NODE;
      vty->index = vr_name;
      return CMD_SUCCESS;
   }

   /* If the row doesn't exist, create new one if maximim limits are not reached */

   /* Check max VRs Per Router limit */
   if(vrrp_max_vrs_per_router == VRRP_MAX_VRS_PER_RTR)
   {
      vty_out(vty, "Cannot create VR."
              "Maximum number of VRs has already been reached on the router.%s",
            VTY_NEWLINE);
      return CMD_SUCCESS;
   }

   /* Check max VRs Per Router limit */
   if((port_row->n_virtual_ip4_routers + port_row->n_virtual_ip6_routers)
       >= VRRP_MAX_VRS_PER_IFACE)
   {
      vty_out(vty, "Cannot create VR."
           "Maximum number of VRs has already been reached on the interface.%s",
              VTY_NEWLINE);
      return CMD_SUCCESS;
   }

   txn = cli_do_config_start();
   if (txn == NULL)
   {
#ifdef VRRP_CLI_DEBUG
      vty_out(vty, "cli_do_config_start() failed.%s",
              VTY_NEWLINE);
#endif /* VRRP_CLI_DEBUG*/
      VLOG_DBG("Transaction creation failed by %s. Function=%s, Line=%d",
             " cli_do_config_start()", __func__, __LINE__);
      cli_do_config_abort(txn);
      return CMD_OVSDB_FAILURE;
   }

   vr_row = ovsrec_vrrp_insert(txn);

   if (vr_row != NULL)
   {
      vty_out(vty, "New VR row %ld added : %s %s", vr_row, (char *)vty->index, VTY_NEWLINE);
   }

   vrrp_ovsrec_insert_ip4_vr_to_port(port_row, vr_row, vrid);

   status = cli_do_config_finish(txn);
   if(status == TXN_SUCCESS || status == TXN_UNCHANGED)
   {
      vrrp_max_vrs_per_router++;
      vty->node = VRRP_IF_NODE;
      vty->index = vr_name;
#ifdef VRRP_CLI_DEBUG
      vty_out(vty, "VR creation success : %s %s", (char *)vty->index, VTY_NEWLINE);
#endif /* VRRP_CLI_DEBUG*/
      return CMD_SUCCESS;
   }
   else
   {
#ifdef VRRP_CLI_DEBUG
      vty_out(vty, "Transaction commit failed.%s",
              VTY_NEWLINE);
#endif /* VRRP_CLI_DEBUG*/
      VLOG_ERR("Transaction commit failed in function=%s, line=%d",__func__,__LINE__);
      return CMD_OVSDB_FAILURE;
   }
}

DEFUN (cli_vrrp_create_vr_group,
       cli_vrrp_create_vr_group_cmd,
       "vrrp <1-255> address-family (ipv4 | ipv6)",
       "Creates a virtual router group\n"
       "Creates a virtual router group, the range is 1-255\n"
       "Enter address family\n"
       "Address family\n")

{
   return vrrp_create_vr_group((char *)vty->index, atoi(argv[0]), argv[1]);
}

DEFUN_HIDDEN (cli_vrrp_add_ip,
              cli_vrrp_add_ip_cmd,
              "ip address A.B.C.D {secondary}",
              IP_STR
              "Set virtual IP address\n"
              "Set as secondary virtual IP address")
{
   return ;
}

DEFUN (cli_vrrp_exit_vrrp_if_mode,
       cli_vrrp_exit_vrrp_if_mode_cmd,
       "exit",
       "Exit current mode and down to previous mode\n")
{
  return;
}


/*
 * Function: cli_post_init
 * Responsibility: Initialize VRRP cli element.
 */
void cli_post_init(void)
{
   return;
}
