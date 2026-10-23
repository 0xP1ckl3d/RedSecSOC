"""Bounded partial evidence search with literal terms and AND/OR grouping."""
import ipaddress
import shlex

SEARCH_FIELDS=['rule.description','rule.id','agent.name','agent.ip','full_log','decoder.name','location']
SEARCH_FIELDS+=['data.win.eventdata.'+x for x in ('image','parentImage','sourceImage','targetImage','newProcessName','parentProcessName','commandLine','processCommandLine','parentCommandLine','scriptBlockText','path','targetFilename','imageLoaded','objectName','targetObject','details','user','targetUserName','subjectUserName','targetDomainName','subjectDomainName','taskName','taskContent','serviceName','imagePath','serviceFileName','sourceHostname','destinationHostname','queryName','queryResults','pipeName','product','description','originalFileName','hashes')]
SEARCH_FIELDS+=['data.'+x for x in ('src_ip','dest_ip','srcip','dstip','app_proto','proto','protocol','event_type','http.hostname','http.url','http.http_method','http.http_user_agent','dns.rrname','dns.query.rrname','tls.sni','tls.subject','alert.signature','alert.signature_id','alert.category','integration','action','name','image','actor_id','id','Actor.Attributes.name','Actor.Attributes.image','docker.Actor.Attributes.name','docker.Actor.Attributes.image','container.image.name','container.name','audit.exe','audit.command','audit.key','audit.auid','audit.type','audit.cwd','file','path','exe','command','process.name','srcuser','dstuser','user','package','version','sca.policy','sca.check.title','sca.check.description','sca.check.rationale','sca.check.remediation','vulnerability.cve','vulnerability.title','vulnerability.package.name','vulnerability.package.version','reason','status','operation')]
SEARCH_FIELDS+=['syscheck.'+x for x in ('path','event','diff','uname_after','uname_before','gname_after','gname_before','sha256_after','sha256_before')]
SEARCH_FIELDS+=['source.domain','destination.domain','process.executable','process.command_line','file.path','user.name','url.full','dns.question.name']

def terms_query(q,fields,assets):
    lexer=shlex.shlex(q,posix=False,punctuation_chars='()');lexer.whitespace_split=True;lexer.commenters=''
    try:tokens=list(lexer)
    except ValueError:raise ValueError('Close the quoted search phrase')
    if not tokens:return {'match_all':{}}
    literal_count=sum(t not in ('AND','OR','(',')') for t in tokens)
    if literal_count>6:raise ValueError('Use up to six search terms, or put a longer phrase in quotes')
    if len(tokens)>30:raise ValueError('Search expression is too complex')
    pos=0
    def term(value):
        if value.startswith('"') and value.endswith('"'):value=value[1:-1]
        if not value:raise ValueError('Enter a non-empty search term')
        pattern='*'+value.replace('\\','\\\\').replace('*','\\*').replace('?','\\?')+'*'
        choices=[{'wildcard':{field:{'value':pattern,'case_insensitive':True}}} for field in fields]
        choices.append({'multi_match':{'query':value,'fields':['full_log','rule.description'],'type':'phrase','lenient':True}})
        ips=[ip for ip,r in assets.get('addresses',{}).items() if value.casefold() in r['name'].casefold() or value in ip]
        try:ips.append(str(ipaddress.ip_address(value)))
        except ValueError:pass
        if ips:
            choices.extend({'terms':{field:list(set(ips))}} for field in ['agent.ip','data.src_ip','data.dest_ip','data.srcip','data.dstip','data.win.eventdata.sourceIp','data.win.eventdata.destinationIp','source.ip','destination.ip'])
        return {'bool':{'should':choices,'minimum_should_match':1}}
    def primary(depth=0):
        nonlocal pos
        if depth>4 or pos>=len(tokens):raise ValueError('Check search operators and parentheses')
        token=tokens[pos];pos+=1
        if token=='(':
            result=expression(depth+1)
            if pos>=len(tokens) or tokens[pos]!=')':raise ValueError('Close the search parentheses')
            pos+=1;return result
        if token in ('AND','OR',')'):raise ValueError('Place AND/OR between search terms')
        return term(token)
    def conjunction(depth):
        nonlocal pos
        parts=[primary(depth)]
        while pos<len(tokens) and tokens[pos] not in ('OR',')'):
            if tokens[pos]=='AND':pos+=1
            parts.append(primary(depth))
        return parts[0] if len(parts)==1 else {'bool':{'must':parts}}
    def expression(depth):
        nonlocal pos
        parts=[conjunction(depth)]
        while pos<len(tokens) and tokens[pos]=='OR':pos+=1;parts.append(conjunction(depth))
        return parts[0] if len(parts)==1 else {'bool':{'should':parts,'minimum_should_match':1}}
    result=expression(0)
    if pos!=len(tokens):raise ValueError('Check search parentheses')
    return result

def network_filter():
    choices=[{'exists':{'field':f}} for f in ['data.src_ip','data.dest_ip','data.srcip','data.dstip','data.win.eventdata.sourceIp','data.win.eventdata.destinationIp','source.ip','destination.ip']]
    choices.append({'bool':{'filter':[{'terms':{'data.win.system.eventID':['3','22']}},{'wildcard':{'data.win.system.channel':{'value':'*Sysmon*','case_insensitive':True}}}]}})
    choices.append({'exists':{'field':'data.event_type'}})
    return {'bool':{'should':choices,'minimum_should_match':1}}

def protocol_filter(protocol):
    p=protocol.lower();aliases={'kerberos':['krb5','kerberos'],'smb':['smb','smb2','smb3'],'http':['http','http2'],'icmp':['icmp','icmpv6']}.get(p,[p])
    choices=[{'terms':{field:list(dict.fromkeys(aliases+[a.upper() for a in aliases]))}} for field in ['data.app_proto','data.event_type','data.proto','data.protocol','data.win.eventdata.protocol','network.protocol','network.transport']]
    if p=='dns':choices.append({'bool':{'filter':[{'term':{'data.win.system.eventID':'22'}},{'wildcard':{'data.win.system.channel':{'value':'*Sysmon*','case_insensitive':True}}}]}})
    return {'bool':{'should':choices,'minimum_should_match':1}}

def port_filter(port):
    return {'bool':{'should':[{'term':{f:port}} for f in ['data.src_port','data.dest_port','data.srcport','data.dstport','data.win.eventdata.sourcePort','data.win.eventdata.destinationPort','source.port','destination.port']],'minimum_should_match':1}}
