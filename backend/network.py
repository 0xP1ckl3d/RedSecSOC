"""Network presentation enrichment; preserves event identity and raw evidence."""
import ipaddress
from engine import flatten,text
from addresses import classify_address

PORTS={1900:'SSDP',22:'SSH',25:'SMTP',53:'DNS',80:'HTTP',88:'Kerberos',123:'NTP',135:'RPC',139:'NetBIOS/SMB',389:'LDAP',443:'HTTPS',445:'SMB',464:'Kerberos',465:'SMTPS',514:'Syslog',587:'SMTP submission',636:'LDAPS',993:'IMAPS',1433:'MSSQL',1514:'Wazuh agent transport',1515:'Wazuh enrollment',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5985:'WinRM',5986:'WinRM over TLS',8080:'HTTP alternate',8443:'HTTPS alternate'}
PROTOCOLS={'smb':'SMB','smb2':'SMB','smb3':'SMB','tls':'TLS','http':'HTTP','http2':'HTTP/2','dns':'DNS','dcerpc':'DCERPC','krb5':'Kerberos','ldap':'LDAP','ssh':'SSH','rdp':'RDP','quic':'QUIC','smtp':'SMTP','dhcp':'DHCP','mdns':'mDNS','nfs':'NFS','ntp':'NTP','ftp':'FTP','mqtt':'MQTT','rdp':'RDP'}

def endpoint(ip,recorded,assets):
    record=assets.get('addresses',{}).get(ip,{})
    if recorded and text(recorded).strip() not in ('-','unknown'):
        return {'ip':ip,'name':text(recorded),'label':text(recorded),'basis':'Hostname recorded in this event'}
    if record:
        return {'ip':ip,'name':record['name'],'label':record['name'],'basis':record['source'],'observed':record.get('observed')}
    return {'ip':ip,'name':'','label':ip or 'unrecorded endpoint','basis':'IP address only; name unresolved'}

def enrich_network(event,source,assets):
    if event['family'] not in ('Network activity','Network detection','Network connection'):return event
    f=flatten(source);identity=event['identity'];src=identity['source_ip'];dst=identity['destination_ip']
    if not src and not dst:return event
    src_key=next((k for k in ('data.src_ip','data.srcip','data.win.eventdata.sourceIp','source.ip') if f.get(k)), 'source.ip')
    dst_key=next((k for k in ('data.dest_ip','data.dstip','data.win.eventdata.destinationIp','destination.ip') if f.get(k)), 'destination.ip')
    a=endpoint(src,f.get('data.win.eventdata.sourceHostname') or f.get('source.domain'),assets)
    # HTTP Host and TLS SNI describe the requested name, not a verified machine identity.
    a.update(classify_address(src))
    recorded_dst=f.get('data.win.eventdata.destinationHostname') or f.get('destination.domain')
    b=endpoint(dst,recorded_dst,assets);b.update(classify_address(dst))
    requested=f.get('data.tls.sni') or f.get('data.http.hostname')
    if not b['name'] and requested:b.update(name=text(requested),label=text(requested),basis='Requested server name recorded in TLS SNI / HTTP Host')
    protocol=text(f.get('data.app_proto') or f.get('network.protocol')).lower()
    service=PROTOCOLS.get(protocol,protocol.upper() if protocol not in ('','unknown','failed') else '')
    field='data.app_proto' if f.get('data.app_proto') else 'network.protocol';basis='Application protocol recorded by the sensor';inferred=False
    if not service:
        for key in ('data.event_type',):
            if text(f.get(key)).lower() in PROTOCOLS:service=PROTOCOLS[text(f[key]).lower()];field=key;basis='Protocol-specific record emitted by the sensor';break
    if not service:
        for keys in [('data.dest_port','data.dstport','data.win.eventdata.destinationPort','destination.port'),('data.src_port','data.srcport','data.win.eventdata.sourcePort','source.port')]:
            key=next((k for k in keys if f.get(k) is not None),None)
            try:port=int(f.get(key,0))
            except (TypeError,ValueError):port=0
            if port in PORTS:service=PORTS[port];field=key;basis=f'Inferred from port {port}; application protocol is not confirmed';inferred=True;break
    if not service:
        field=next((k for k in ('data.proto','data.protocol','data.win.eventdata.protocol','network.transport') if f.get(k)), 'network.transport')
        service=text(f.get(field)).upper() or 'IP';basis='Recorded transport; application protocol unavailable'
    service_label=('Possible '+service) if inferred else service
    summary=f'{service_label} from {a["label"]} to {b["label"]}'
    if not event['is_alert']:event['title']='Network activity: '+summary
    event['subject']=summary
    items=[]
    for label,node,key in [('Source endpoint',a,src_key),('Destination endpoint',b,dst_key)]:
        items.append({'label':label,'value':node['label']+(f' ({node["ip"]})' if node['name'] and node['ip'] else ''),'field':key,'kind':'text','transformation':node['basis']})
    # Enrichment is additive. Keep the destination port among the first three
    # quick facts, including for clients still displaying the original layout.
    port_fields=[('Destination port',('data.dest_port','data.dstport','data.win.eventdata.destinationPort','destination.port')),('Source port',('data.src_port','data.srcport','data.win.eventdata.sourcePort','source.port'))]
    for label,keys in port_fields[:1]:
        key=next((k for k in keys if f.get(k) is not None),None)
        items.append({'label':label,'value':f[key] if key else 'Not recorded','field':key or 'destination.port','kind':'text'})
    items.append({'label':'Service estimate' if inferred else 'Application protocol' if protocol or f.get('data.event_type') in PROTOCOLS else 'Protocol / service','value':service_label,'field':field,'kind':'text','transformation':basis})
    for label,keys in port_fields[1:]:
        key=next((k for k in keys if f.get(k) is not None),None)
        if key:items.append({'label':label,'value':f[key],'field':key,'kind':'text'})
    transport_key=next((k for k in ('data.proto','data.protocol','data.win.eventdata.protocol','network.transport') if f.get(k)),None)
    if transport_key:items.append({'label':'Transport','value':text(f[transport_key]).upper(),'field':transport_key,'kind':'text'})
    event['facts']=items+event['facts'];event['evidence']['Network interpretation']=items
    event['network_context']={'service':service,'service_inferred':inferred,'service_basis':basis,'source':a,'destination':b,'inventory_updated':assets.get('updated')}
    if any('inventory' in node['basis'].lower() for node in (a,b)):
        event['observations'].append('Endpoint names marked as inventory enrichment use the current manager/approved asset inventory, not a historical DNS assertion. Original addresses remain in the evidence.')
    if inferred:event['gaps'].append(basis+'.')
    return event
