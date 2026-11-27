<?php
/**
 * Isolated regression test. Run: php tests/test-certificate-listener.php
 * No OMV installation, root privileges, database writes or service reloads.
 */
namespace OMV\Engine\Module {
    abstract class ServiceAbstract
    {
        public $dirtyCalls = 0;
        public function setDirty() { ++$this->dirtyCalls; }
    }
    interface IServiceStatus {}
}
namespace OMV\Engine\Notify {
    interface IListener {}
}
namespace OMV\Config {
    // Deliberately does not implement ArrayAccess, like OMV ConfigObject.
    class ConfigObject
    {
        private $data;
        public function __construct(array $data) { $this->data = $data; }
        public function getAssoc() { return $this->data; }
    }
    class Database
    {
        public static $webadmin = [];
        public static function getInstance() { return new self(); }
        public function get($id)
        {
            if ($id !== 'conf.webadmin') {
                throw new \RuntimeException('Unexpected configuration model');
            }
            return new ConfigObject(self::$webadmin);
        }
        public function getAssoc($id) { return $this->get($id)->getAssoc(); }
    }
}
namespace {
    require __DIR__ . '/../usr/share/openmediavault/engined/module/cterm.inc';

    $cases = [
        ['selected certificate', ['sslcertificateref' => 'selected'], ['uuid' => 'selected'], 1],
        ['unrelated certificate', ['sslcertificateref' => 'selected'], ['uuid' => 'other'], 0],
        ['empty reference', ['sslcertificateref' => ''], ['uuid' => 'selected'], 0],
        ['missing reference', [], ['uuid' => 'selected'], 0],
        ['missing event UUID', ['sslcertificateref' => 'selected'], [], 0],
        ['null event UUID', ['sslcertificateref' => 'selected'], ['uuid' => null], 0],
    ];
    foreach ($cases as [$name, $webadmin, $event, $expected]) {
        \OMV\Config\Database::$webadmin = $webadmin;
        $module = new \OMVModuleCTerm();
        try {
            $module->onModifySslCertificate(0, 'org.openmediavault.conf.system.certificate.ssl', $event);
            if ($module->dirtyCalls !== $expected) {
                throw new \RuntimeException('Unexpected number of setDirty calls');
            }
        } catch (\Throwable $error) {
            fwrite(STDERR, "FAIL: $name: " . $error->getMessage() . "\n");
            exit(1);
        }
        echo "PASS: $name\n";
    }
}
