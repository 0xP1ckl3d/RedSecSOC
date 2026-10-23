"""Address role is independent of inventory membership and threat reputation.

References: IANA IPv4/IPv6 Special-Purpose and Multicast Address registries.
Special-use checks precede is_global: multicast is never public unicast.
"""
import ipaddress

PRIVATE=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
DOCUMENTATION=[ipaddress.ip_network(n) for n in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24','2001:db8::/32','3fff::/20')]
SPECIAL=[ipaddress.ip_network(n) for n in ('0.0.0.0/8','192.0.0.0/24','192.88.99.0/24','198.18.0.0/15','240.0.0.0/4','64:ff9b::/96','64:ff9b:1::/48','100::/64','100:0:0:1::/64','2001::/23','2002::/16','5f00::/16')]
PUBLIC_EXCEPTIONS=[ipaddress.ip_network(n) for n in ('192.0.0.9/32','192.0.0.10/32','2001:1::1/128','2001:1::2/128','2001:1::3/128','2001:3::/32','2001:4:112::/48','2001:20::/28','2001:30::/28')]
LABELS={'public':'Public unicast','private':'RFC 1918 private','unique-local':'IPv6 unique local','loopback':'Loopback','link-local':'Link local','multicast':'Multicast','broadcast':'Limited broadcast','unspecified':'Unspecified','shared':'Shared address space (CGNAT)','documentation':'Documentation range','reserved':'Reserved / special purpose','invalid':'Invalid address'}

def classify_address(value):
    try:
        ip=ipaddress.ip_address(value)
    except ValueError:return {'address_class':'invalid','address_label':LABELS['invalid'],'external':False}
    if ip.version==6 and ip.ipv4_mapped:
        result=classify_address(str(ip.ipv4_mapped))
        return result|{'address_label':'IPv4 mapped · '+result['address_label']}
    if ip.is_unspecified:kind='unspecified'
    elif str(ip)=='255.255.255.255':kind='broadcast'
    elif ip.is_multicast:kind='multicast'
    elif ip.is_loopback:kind='loopback'
    elif ip.is_link_local:kind='link-local'
    elif any(ip in n for n in PRIVATE if n.version==ip.version):kind='private'
    elif ip.version==6 and ip in ipaddress.ip_network('fc00::/7'):kind='unique-local'
    elif ip.version==4 and ip in ipaddress.ip_network('100.64.0.0/10'):kind='shared'
    elif any(ip in n for n in DOCUMENTATION if n.version==ip.version):kind='documentation'
    elif any(ip in n for n in PUBLIC_EXCEPTIONS if n.version==ip.version):kind='public'
    elif any(ip in n for n in SPECIAL if n.version==ip.version):kind='reserved'
    elif ip.is_reserved or not ip.is_global:kind='reserved'
    else:kind='public'
    return {'address_class':kind,'address_label':LABELS[kind],'external':kind=='public'}
