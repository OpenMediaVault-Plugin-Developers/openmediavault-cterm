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

    public function deployAfter(): array
    {
        return ["nginx", "certificates"];
    }

    final public function onModifySslCertificate($type, $path, $object)
    {
        $db = \OMV\Config\Database::getInstance();
        $webadmin = $db->get("conf.webadmin");
        if (!empty($webadmin['sslcertificateref']) &&
            isset($object['uuid']) &&
            $webadmin['sslcertificateref'] === $object['uuid']) {
            $this->setDirty();
        }
    }

    final public function onModifyWebAdmin($type, $path, $object)
    {
        $this->setDirty();
    }

    public function bindListeners(\OMV\Engine\Notify\Dispatcher $dispatcher)
    {
        $dispatcher->addListener(
            OMV_NOTIFY_MODIFY,
            "org.openmediavault.conf.service.cterm",
            [$this, "setDirty"]
        );
        $dispatcher->addListener(
            OMV_NOTIFY_MODIFY,
            "org.openmediavault.conf.system.certificate.ssl",
            [$this, "onModifySslCertificate"]
        );
        $dispatcher->addListener(
            OMV_NOTIFY_MODIFY,
            "org.openmediavault.conf.webadmin",
            [$this, "onModifyWebAdmin"]
        );
        $dispatcher->addListener(
            OMV_NOTIFY_MODIFY,
            "org.openmediavault.conf.system.nginx",
            [$this, "setDirty"]
        );
    }
}
