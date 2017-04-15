<?php
/**
 * IPGroup Plugin
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Sascha Bendix <sascha.bendix@localroot.de>
 * @author     Marcel Pennewiss <opensource@pennewiss.de>
 * @author     Peter Grosse <pegro@fem-net.de>
 * @author     Phy25 <ipgroup2@phy25.com>
 */

if(!defined('DOKU_INC')) die();

class action_plugin_ipgroup2 extends DokuWiki_Action_Plugin {

    /**
     * Register event handlers
     */
    function register(Doku_Event_Handler $controller) {
        $controller->register_hook('AUTH_ACL_CHECK', 'BEFORE', $this, 'modifyGroups');
    }

    function modifyGroups(&$event, $param) {
        // get remote ip when user is using a proxy
        $ip = clientIP(true);

        // read config file or create
        $filecontent = @file(DOKU_CONF.'ipgroup.conf', FILE_SKIP_EMPTY_LINES);
        if ($filecontent === false) { $filecontent = array(); }

        // check current ip against each network-definition
        foreach ($filecontent as $line) {
            // seperate network and group and trim spaces
            list($network,$group) = explode(';', $line);
            $network = rtrim($network);
            $group = rtrim($group);

            // seperate cidr-suffix from network
            $network_bits = substr($network,strpos($network,'/')+1);

            // only go further if the acces is done via the same ip version then the network we are currently looking at
            if (filter_var($network_address,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4) == filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4)
                || (filter_var($network_address,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6) == filter_var($ip,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6))) {

                // check if ip matches network
                if ($this->ip2pton($ip."/".$network_bits) === $this->ip2pton($network)) {
                    // add group to list
                    $groups[] = $group;
                }
            }
        }

        if (count($groups) > 0) {
            // merge existing group-informations and new groups
            $grps = array_merge((array) $event->data['groups'], $groups);
            // remove duplicate entries
            $grps = array_values(array_unique($grps));

            // Overwrite Permissions
            $event->data['groups'] = $grps;
        }
    }

    /**
     * calc ip-adress to in_addr-representation
     * @link http://www.php.net/manual/de/function.inet-pton.php#93501 source and idea
     */
    function ip2pton($ipaddr) {

        // Strip out the netmask, if there is one.
        $cx = strpos($ipaddr, '/');
        if ($cx)
        {
            $subnet = (int)(substr($ipaddr, $cx+1));
            $ipaddr = substr($ipaddr, 0, $cx);
        }
        else $subnet = null; // No netmask present

        // Convert address to packed format
        $addr = inet_pton($ipaddr);

        // Convert the netmask
        if (is_integer($subnet))
        {
            // Maximum netmask length = same as packed address
            $len = 8*strlen($addr);
            if ($subnet > $len) $subnet = $len;

            // Create a hex expression of the subnet mask
            $mask  = str_repeat('f', $subnet>>2);
            switch($subnet & 3)
            {
                case 3: $mask .= 'e'; break;
                case 2: $mask .= 'c'; break;
                case 1: $mask .= '8'; break;
            }
            $mask = str_pad($mask, $len>>2, '0');

            // Packed representation of netmask
            $mask = pack('H*', $mask);
        }

        // Return logical and of addr and mask
        return ($addr & $mask);
    }
}
