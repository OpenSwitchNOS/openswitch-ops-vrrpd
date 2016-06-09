# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch Test for VRRP global enable and disable.
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division


TOPOLOGY = """
#
# +-------+     +-------+
# |       |     |       |
# |       +-----+       |
# | Sw1   +-----+   Sw2 |
# |       |     |       |
# +-------+     +-------+
#
# Nodes
[type=openswitch name="OpenSwitch 1"] sw1
[type=openswitch name="OpenSwitch 2"] sw2

# Links
sw1:1 -- sw2:1
"""


def test_vrrp_enable_disable(topology):
    with sw1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.no_shutdown()
    with sw2.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.no_shutdown()
