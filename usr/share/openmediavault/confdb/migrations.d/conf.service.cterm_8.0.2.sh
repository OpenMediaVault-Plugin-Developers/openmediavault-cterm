#!/bin/sh

set -e

. /etc/default/openmediavault
. /usr/share/openmediavault/scripts/helper-functions

if ! omv_config_exists "/config/services/cterm/enablenginx"; then
  omv_config_add_key "/config/services/cterm" "enablenginx" "0"
  omv_module_set_dirty cterm
fi

exit 0
