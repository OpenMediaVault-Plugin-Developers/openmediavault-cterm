#!/bin/sh

set -e

. /etc/default/openmediavault
. /usr/share/openmediavault/scripts/helper-functions

if ! omv_config_exists "/config/services/cterm/autosecret"; then
  omv_config_add_key "/config/services/cterm" "autosecret" ""
  omv_module_set_dirty cterm
fi

if ! omv_config_exists "/config/services/cterm/autouser"; then
  omv_config_add_key "/config/services/cterm" "autouser" ""
fi

exit 0
