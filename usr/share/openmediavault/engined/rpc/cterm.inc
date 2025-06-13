<?php
/**
 * Copyright (C) 2022-2025 openmediavault plugin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

class OMVRpcServiceCterm extends \OMV\Rpc\ServiceAbstract
{
    public function getName()
    {
        return "Cterm";
    }

    public function initialize()
    {
        $this->registerMethod("get");
        $this->registerMethod("set");
    }

    public function get($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // Get the configuration object.
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.cterm");
        $webadmin = $db->get("conf.webadmin");
        $object->add("ssl", "string", boolval($webadmin->get("enablessl")) ? "https" : "");
        $autouser = $object->get('autouser') ?: $context['username'];
        $object->add("omvuser", "string", $autouser);
        $secret = trim(file_get_contents('/etc/omv_cterm.secret'));
        $ts = sprintf('%s', microtime(true));
        $userts = sprintf('%s:%s', $autouser, $ts);
        $hmac = hash_hmac('sha256', $userts, $secret);
        $object->add("hmac", "string", $hmac);
        $object->add("ts", "string", $ts);
        // Return the configuration object.
        return $object->getAssoc();
    }

    public function set($params, $context)
    {
        // Validate the RPC caller context.
        $this->validateMethodContext($context, ["role" => OMV_ROLE_ADMINISTRATOR]);
        // remove unneeded params
        unset($params["ssl"], $params["omvuser"], $params["hmac"], $params["ts"]);
        // Validate the parameters of the RPC service method.
        $this->validateMethodParams($params, "rpc.cterm.set");
        $len = strlen($params["autosecret"]);
        if ($len > 0 && $len < 32) {
            $msg = gettext("Auto-login secret is too short.  Must be at least 32 characters or disabled with 0 characters.");
            throw new \OMV\Exception($msg);
        }
        $params['basepath'] = '/' . trim($params['basepath'], '/');
        $db = \OMV\Config\Database::getInstance();
        $object = $db->get("conf.service.cterm");
        $object->setAssoc($params);
        $db->set($object);
        // Return the configuration object.
        return $object->getAssoc();
    }
}
