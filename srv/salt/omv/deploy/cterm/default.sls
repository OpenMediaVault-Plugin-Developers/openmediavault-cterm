# @license   http://www.gnu.org/licenses/gpl.html GPL Version 3
# @author    OpenMediaVault Plugin Developers <plugins@omv-extras.org>
# @copyright Copyright (c) 2025 openmediavault plugin developers
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

{% set config = salt['omv_conf.get']('conf.service.cterm') %}
{% set webadmin = salt['omv_conf.get']('conf.webadmin') %}

{% if config.enable | to_bool %}

configure_cterm:
  file.managed:
    - name: "/etc/omv_cterm.conf"
    - source:
      - salt://{{ tpldir }}/files/etc-omv_cterm_conf.j2
    - template: jinja
    - context:
        config: {{ config | json }}
        webadmin: {{ webadmin | json }}
    - user: root
    - group: root
    - mode: '644'

configure_cterm_secret:
  file.managed:
    - name: "/etc/omv_cterm.secret"
    - contents: "{{ config.autosecret }}"
    - user: root
    - group: root
    - mode: '0600'

configure_cterm_unit:
  file.managed:
    - name: "/etc/systemd/system/omv_cterm.service"
    - source:
      - salt://{{ tpldir }}/files/unit.j2
    - template: jinja
    - context:
        config: {{ config | json }}
        webadmin: {{ webadmin | json }}
    - user: root
    - group: root
    - mode: '644'

systemd_daemon_reload_cterm:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: configure_cterm
      - file: configure_cterm_unit

start_cterm_service:
  service.running:
    - name: omv_cterm
    - enable: True
    - watch:
      - file: configure_cterm
      - file: configure_cterm_unit
      - file: configure_cterm_secret

{% else %}

stop_cterm_service:
  service.dead:
    - name: omv_cterm
    - enable: False

remove_cterm_unit:
  file.absent:
    - name: "/etc/systemd/system/omv_cterm.service"

systemd_daemon_reload_cterm2:
  cmd.run:
    - name: systemctl daemon-reload
    - onchanges:
      - file: remove_cterm_unit

{% endif %}
