#!/bin/sh
#
# @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
# @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
# @copyright Copyright (c) 2022-2025 openmediavault plugin developers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

set -e

. /etc/default/openmediavault
. /usr/share/openmediavault/scripts/helper-functions

if ! omv_config_exists "/config/services/cterm"; then
  omv_config_add_node "/config/services" "cterm"
  omv_config_add_key "/config/services/cterm" "enable" 0
  omv_config_add_key "/config/services/cterm" "host" "0.0.0.0"
  omv_config_add_key "/config/services/cterm" "port" "5000"
  omv_config_add_key "/config/services/cterm" "hostshell" "0"
  omv_config_add_key "/config/services/cterm" "autosecret" ""
  omv_config_add_key "/config/services/cterm" "autouser" ""
  omv_config_add_key "/config/services/cterm" "basepath" ""
fi

exit 0
