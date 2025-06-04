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
    - mode: 644

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
    - mode: 644

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
