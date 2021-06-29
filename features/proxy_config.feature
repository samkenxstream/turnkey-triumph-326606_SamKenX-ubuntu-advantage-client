@uses.config.contract_token
Feature: Proxy configuration

    @series.lts
    Scenario Outline: Attach command when proxy is configured
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I launch a `focal` `proxy` machine
        And I run `apt install squid -y` `with sudo` on the `proxy` machine
        And I add this text on `/etc/squid/squid.conf` on `proxy` above `http_access deny all`:
            """
            dns_v4_first on\nacl all src 0.0.0.0\/0\nhttp_access allow all
            """
        And I run `systemctl restart squid.service` `with sudo` on the `proxy` machine
        And I configure uaclient `http` proxy to use `proxy` machine
        And I configure uaclient `https` proxy to use `proxy` machine
        And I verify `/var/log/squid/access.log` is empty on `proxy` machine
        And I attach `contract_token` with sudo
        And I run `cat /var/log/squid/access.log` `with sudo` on the `proxy` machine
        Then stdout matches regexp:
        """
        .*CONNECT contracts.canonical.com.*
        """
        When I run `truncate -s 0 /var/log/squid/access.log` `with sudo` on the `proxy` machine
        And I configure uaclient `apt_http` proxy to use `proxy` machine
        And I configure uaclient `apt_https` proxy to use `proxy` machine
        And I verify `/var/log/squid/access.log` is empty on `proxy` machine
        Then I verify that no files exist matching `/etc/apt/apt.conf.d/90ubuntu-advantage-aptproxy`
        When I run `ua refresh config` with sudo
        Then stdout matches regexp:
        """
        Setting APT proxy
        """
        Then I verify that files exist matching `/etc/apt/apt.conf.d/90ubuntu-advantage-aptproxy`
        When I run `cat /etc/apt/apt.conf.d/90ubuntu-advantage-aptproxy` with sudo
        Then stdout matches regexp:
        """
        /\*
         \* Autogenerated by ubuntu-advantage-tools
         \* Do not edit this file directly
         \*
         \* To change what ubuntu-advantage-tools sets here, edit the apt_http_proxy
         \* and apt_https_proxy fields in /etc/ubuntu-advantage/uaclient.conf. Then
         \* run "ua refresh config".
         \*/
        Acquire::http::Proxy ".*";
        Acquire::https::Proxy ".*";
        """
        When I run `apt update` with sudo
        And I run `cat /var/log/squid/access.log` `with sudo` on the `proxy` machine
        Then stdout matches regexp:
        """
        .*GET.*ubuntu.com/ubuntu/dists.*
        """
        When I append the following on uaclient config
        """
        ua_config:
            apt_http_proxy: ""
            apt_https_proxy: ""
        """
        And I run `ua refresh config` with sudo
        Then I verify that no files exist matching `/etc/apt/apt.conf.d/90ubuntu-advantage-aptproxy`
        When I append the following on uaclient config
        """
        ua_config:
            apt_http_proxy: "invalidurl"
            apt_https_proxy: "invalidurls"
        """
        And I verify that running `ua refresh config` `with sudo` exits `1`
        Then stderr matches regexp:
        """
        "invalidurl" is not a valid url. Not setting as proxy.
        """
        When I append the following on uaclient config
        """
        ua_config:
            apt_https_proxy: "https://localhost:12345"
        """
        And I verify that running `ua refresh config` `with sudo` exits `1`
        Then stderr matches regexp:
        """
        "https://localhost:12345" is not working. Not setting as proxy.
        """

        Examples: ubuntu release
           | release |
           | xenial  |
           | bionic  |
           | focal   |

    @series.xenial
    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attach command when proxy is configured
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I launch a `focal` `proxy` machine
        And I run `apt install squid -y` `with sudo` on the `proxy` machine
        And I add this text on `/etc/squid/squid.conf` on `proxy` above `http_access deny all`:
            """
            dns_v4_first on\nacl all src 0.0.0.0\/0\nhttp_access allow all
            """
        And I run `systemctl restart squid.service` `with sudo` on the `proxy` machine
        And I configure uaclient `http` proxy to use `proxy` machine
        And I configure uaclient `https` proxy to use `proxy` machine
        And I verify `/var/log/squid/access.log` is empty on `proxy` machine
        And I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        Setting snap proxy
        """
        Then stdout matches regexp:
        """
        Setting Livepatch proxy
        """
        When I run `canonical-livepatch config check-interval=0` with sudo
        And I run `canonical-livepatch refresh` with sudo
        And I run `cat /var/log/squid/access.log` `with sudo` on the `proxy` machine
        Then stdout matches regexp:
        """
        .*CONNECT contracts.canonical.com.*
        """
        When I run `cat /var/log/squid/access.log` `with sudo` on the `proxy` machine
        Then stdout matches regexp:
        """
        .*CONNECT api.snapcraft.io:443.*
        """
        When I run `sleep 120` as non-root
        And I run `cat /var/log/squid/access.log` `with sudo` on the `proxy` machine
        Then stdout matches regexp:
        """
        .*CONNECT livepatch.canonical.com:443.*
        """
        When I run `ua refresh config` with sudo
        Then I will see the following on stdout:
            """
            Setting snap proxy
            Setting Livepatch proxy
            Successfully processed your ua configuration.
            """
        When I append the following on uaclient config
        """
        ua_config:
            http_proxy: ""
            https_proxy: ""
        """
        And I run `ua refresh config` with sudo
        Then I will see the following on stdout:
        """
        No proxy set in config; however, proxy is configured for: snap, livepatch.
        See https://discourse.ubuntu.com/t/ubuntu-advantage-client/21788 for more information on ua proxy configuration.

        Successfully processed your ua configuration.
        """
        When I append the following on uaclient config
        """
        ua_config:
            http_proxy: "invalidurl"
            https_proxy: "invalidurls"
        """
        And I verify that running `ua refresh config` `with sudo` exits `1`
        Then stderr matches regexp:
        """
        "invalidurl" is not a valid url. Not setting as proxy.
        """
        When I append the following on uaclient config
        """
        ua_config:
            https_proxy: "https://localhost:12345"
        """
        And I verify that running `ua refresh config` `with sudo` exits `1`
        Then stderr matches regexp:
        """
        "https://localhost:12345" is not working. Not setting as proxy.
        """

        Examples: ubuntu release
           | release |
           | xenial  |
           | bionic  |
