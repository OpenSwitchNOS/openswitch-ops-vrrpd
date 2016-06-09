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

#include "vtysh/lib/version.h"
#include "getopt.h"
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


#define MAX_IFINDEX 512

int vrrp_max_vrs_per_router = 0;
int vrrp_max_vrs_per_iface[MAX_IFINDEX];

VLOG_DEFINE_THIS_MODULE(vtysh_vrrpp_cli);



/*
 * Function: vrrp_ovsdb_init
 * Responsibility : Add tables/columns needed for VRRP config commands.
 */
static void vrrp_ovsdb_init()
{
   return;
}

/*
 * Function: cli_pre_init
 * Responsibility : Initialize VRRP cli node.
 */
void cli_pre_init(void)
{

  /* Add tables/columns needed for vrrp config commands. */
  vrrp_ovsdb_init();

}


DEFUN (cli_vrrp_create_vr_group,
       cli_vrrp_create_vr_group_cmd,
       "vrrp <1-255> address-family (ipv4 | ipv6)",
       "Creates a virtual router group\n"
       "Creates a virtual router group, the range is 1-255\n")
{
   return CMD_SUCCESS;;
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
