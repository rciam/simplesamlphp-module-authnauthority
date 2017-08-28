# simplesamlphp-module-authnauthority
A SimpleSAMLphp module for generating an attribute with the value(s) of the
<AuthenticatingAuthority> element contained in a SAML authentication response.

The AuthenticatingAuthority is part of the <AuthnContext> element which 
specifies the context of an authentication event. This element can contain
an authentication context class reference, an authentication context
declaration or declaration reference, or both. Its complex AuthnContextType
contains the AuthenticatingAuthority element defined in the SAML 2.0 core
specification as follows: 

    <AuthenticatingAuthority> [Zero or More]
    Zero or more unique identifiers of authentication authorities that were 
    involved in the authentication of the principal (not including the assertion
    issuer, who is presumed to have been involved without being explicitly named
    here).

### Example configuration

Example configuration for the authproc filter in global `config/config.php`:

    authproc.sp = array(
      ...
      '20' => array(
        'class' => 'authnauthority:AuthnAuthority',
        // Uncomment to change the default attribute name
        //'attribute' => 'authnAuthority',
        // By default we replace the existing attribute value (if any);
        // change to false to append the AuthenticatingAuthority values
        //'replace' => true,
      ),

## License

Licensed under the Apache 2.0 license, for details see `LICENSE`.
