<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\Ldap;

use Symfony\Component\Ldap\Adapter\AdapterInterface;
use Symfony\Component\Ldap\Adapter\EntryManagerInterface;
use Symfony\Component\Ldap\Adapter\ExtLdap\Adapter;
use Symfony\Component\Ldap\Adapter\QueryInterface;
use Symfony\Component\Ldap\Exception\DriverNotFoundException;

/**
 * @author Charles Sarrazin <charles@sarraz.in>
 */
final class Ldap implements LdapInterface
{
    private AdapterInterface $adapter;

    public function __construct(AdapterInterface $adapter)
    {
        $this->adapter = $adapter;
    }

    public function bind(?string $dn = null, #[\SensitiveParameter] ?string $password = null): void
    {
        $this->adapter->getConnection()->bind($dn, $password);
    }

    public function sasl_bind(?string $dn = null, #[\SensitiveParameter] ?string $password = null, ?string $mech = null, ?string $realm = null, ?string $authc_id = null, ?string $authz_id = null, ?string $props = null): void
    {
        $this->adapter->getConnection()->sasl_bind($dn, $password, $mech, $realm, $authc_id, $authz_id, $props);
    }

    public function whoami(): string|null
    {
        return $this->adapter->getConnection()->whoami();
    }

    public function query(string $dn, string $query, array $options = []): QueryInterface
    {
        return $this->adapter->createQuery($dn, $query, $options);
    }

    public function getEntryManager(): EntryManagerInterface
    {
        return $this->adapter->getEntryManager();
    }

    public function escape(string $subject, string $ignore = '', int $flags = 0): string
    {
        return $this->adapter->escape($subject, $ignore, $flags);
    }

    /**
     * Creates a new Ldap instance.
     *
     * @param string $adapter The adapter name
     * @param array  $config  The adapter's configuration
     */
    public static function create(string $adapter, array $config = []): static
    {
        if ('ext_ldap' !== $adapter) {
            throw new DriverNotFoundException(sprintf('Adapter "%s" not found. Only "ext_ldap" is supported at the moment.', $adapter));
        }

        return new self(new Adapter($config));
    }
}
