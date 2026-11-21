PUBLIC SUFFIX List

This is a rendition of the following sources:

Publix Suffix List: https://publicsuffix.org/list/public_suffix_list.dat
IANA TLDs: https://data.iana.org/TLD/tlds-alpha-by-domain.txt

Goal of the list here is to have a more strict TLD list including SLD's (or 2LD's).

Use case is to have DNS servers use this list to check queries against before they
forward or recursive to the Internet, preventing unnessary queries and prevent
potential DNS leakage.

It is NOT a policy list, just a list of valid TLD's including SLD's, the list
is optimized to make sure that DNS resolution does not break (no guarantees!).

Syntax used:

- Domain Without starting Dot: Just that domain
- Domain With starting Dot: That domain and all subdomains

(To be used with RouteDNS: https://github.com/folbricht/routedns)

Updated at least once every 24 hours.

DISCLAIMER: Use at own risk.


======================================================================================

EXAMPLE USAGE WITH ROUTEDNS:

See also: https://github.com/folbricht/routedns/issues/216

[groups.pubsuffix]
type = "blocklist-v2"
resolvers = ["nxdomain"] # Default NXDOMAIN when the Publix-Suffix does not exist
blocklist-refresh = 14400
blocklist-resolver = "doh-google" # Forward to google when it is an existing Publix-Suffix
blocklist-source = [
        {name = "PUBSUFFIX", format = "domain", source = "https://raw.githubusercontent.com/cbuijs/accomplist/master/pubsuffix/routedns.pubsuffix.list"},
]

