<?php

class OMVModuleCTerm extends \OMV\Engine\Module\ServiceAbstract
    implements \OMV\Engine\Notify\IListener, \OMV\Engine\Module\IServiceStatus
{
    public function getName()
    {
        return "cterm";
    }

    public function getStatus()
    {
        $systemCtl = new \OMV\System\SystemCtl("omv_cterm");
        return [
            "name" => $this->getName(),
            "title" => gettext("CTerm"),
            "enabled" => $systemCtl->isEnabled(),
            "running" => $systemCtl->isActive()
        ];
    }

    public function bindListeners(\OMV\Engine\Notify\Dispatcher $dispatcher)
    {
        $dispatcher->addListener(
            OMV_NOTIFY_MODIFY,
            "org.openmediavault.conf.service.cterm",
            [ $this, "setDirty" ]
        );
    }
}
