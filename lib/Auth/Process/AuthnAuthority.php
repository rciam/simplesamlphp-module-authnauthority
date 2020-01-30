<?php

namespace SimpleSAML\Module\authnauthority\Auth\Process;

use SimpleSAML\Error;
use SimpleSAML\Logger;

/**
 * authproc filter for generating an attribute with the value(s) of the
 * <AuthenticatingAuthority> element contained in a SAML response. 
 *
 * The AuthenticatingAuthority is part of the <AuthnContext> element which 
 * specifies the context of an authentication event. This element can contain
 * an authentication context class reference, an authentication context
 * declaration or declaration reference, or both. Its complex AuthnContextType
 * contains the AuthenticatingAuthority element defined in the SAML 2.0 core
 * specification as follows: 
 *
 * <AuthenticatingAuthority> [Zero or More]
 * Zero or more unique identifiers of authentication authorities that were 
 * involved in the authentication of the principal (not including the assertion
 * issuer, who is presumed to have been involved without being explicitly named
 * here).
 *
 * Example configuration for the authproc filter in global config/config.php
 *
 *    authproc.sp = [
 *        ...
 *        '20' => [
 *            'class' => 'authnauthority:AuthnAuthority',
 *            // Uncomment to change the default attribute name
 *            //'attribute' => 'authnAuthority',
 *            // By default we replace the existing attribute value (if any);
 *            // change to false to append the AuthenticatingAuthority values
 *            //'replace' => true,
 *            // List of SP entity IDs that should be excluded
 *            //'spBlacklist' => [],
 *        ],
 *    ],
 *
 * @author Nicolas Liampotis <nliam@grnet.gr>
 */
class AuthnAuthority extends \SimpleSAML\Auth\ProcessingFilter
{
    private $attribute = 'authnAuthority';

    private $replace = true;

    // List of SP entity IDs that should be excluded from this filter.
    private $spBlacklist = [];

    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);
        assert('is_array($config)');

        if (array_key_exists('attribute', $config)) {
            if (!is_string($config['attribute'])) {
                Logger::error(
                    "[authnauthority] Configuration error: 'attribute' not a string literal");
                throw new Error\Exception(
                    "authnauthority configuration error: 'attribute' not a string literal");
            }
            $this->attribute = $config['attribute']; 
        }

        if (array_key_exists('replace', $config)) {
            if (!is_bool($config['replace'])) {
                Logger::error(
                    "[authnauthority] Configuration error: 'replace' not a boolean");
                throw new Error\Exception(
                    "authnauthority configuration error: 'replace' not a boolean");
            }
            $this->replace = $config['replace']; 
        }

        if (array_key_exists('spBlacklist', $config)) {
            if (!is_array($config['spBlacklist'])) {
                Logger::error(
                    "[authnauthority] Configuration error: 'spBlacklist' not an array");
                throw new Error\Exception(
                    "authnauthority configuration error: 'spBlacklist' not an array");
            }
            $this->spBlacklist = $config['spBlacklist'];
        }
    }

    public function process(&$state)
    {
        assert('is_array($state)');

        if (!empty($state['SPMetadata']['entityid'])
            && in_array($state['SPMetadata']['entityid'], $this->spBlacklist, true)) {
            Logger::debug(
                "[authnauthority] process: Blacklisted SP "
                . var_export($state['SPMetadata']['entityid'], true)
                . " - Skipping...");
            return;
        }
        if (!empty($state['saml:sp:IdP'])) {
            $authnauthority = $state['saml:sp:IdP'];
            Logger::debug("[authnauthority] process: state['saml:sp:IdP']="
                . var_export($authnauthority, true));
        } else {
            $authnauthority = $state['Source']['entityid'];
            Logger::debug("[authnauthority] process: state['Source']"
                . "['entityid']=" . var_export($authnauthority, true));
        }
        if ($this->replace || empty($state['Attributes'][$this->attribute])) {
            $state['Attributes'][$this->attribute] = [$authnauthority];
        } else {
            $state['Attributes'][$this->attribute] = array_merge(
                $state['Attributes'][$this->attribute],
                $authnauthority
            );
        }
        Logger::debug("[authnauthority] process: updated state['Attributes']"
            . "['" . $this->attribute . "']="
            . var_export($state['Attributes'][$this->attribute], true));
    }
}
