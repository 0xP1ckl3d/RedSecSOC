"""Evidence normalization. No event content is evaluated or executed.

All claims carry source field references. Provider-specific adapters add meaning;
unrecognized fields remain available in the same readable evidence interface.
"""
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone

VERSION = '0.4.0'


def number(value,default=0):
    try:return int(value)
    except (ValueError,TypeError):return default


def flatten(value, prefix='', out=None):
    out = {} if out is None else out
    if isinstance(value, dict):
        for key, child in value.items():
            flatten(child, f'{prefix}.{key}' if prefix else key, out)
    else:
        out[prefix] = value
    return out


def text(value):
    if value is None:
        return ''
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def label(key):
    key = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', key)
    return key.replace('_', ' ').replace('.', ' / ').strip().capitalize()


def epoch(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError):
        return 0


# Windows identifiers are namespaced by host. A PID is deliberately NOT a GUID.
def guid(value):
    value = text(value).lower().strip('{}')
    return value if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) and value != '00000000-0000-0000-0000-000000000000' else ''


def normalize(hit):
    s = hit.get('_source', hit)
    f = flatten(s)
    used = set()
    groups = defaultdict(list)
    facts = []

    def find(*keys):
        for key in keys:
            if key in f and f[key] is not None and text(f[key]).strip() not in ('', '-', 'N/A'):
                return f[key], key
        return None, None

    def add(section, title, *keys, priority=False, kind='text'):
        value, key = find(*keys)
        if key:
            item = {'label': title, 'value': value, 'field': key, 'kind': kind}
            groups[section].append(item)
            used.add(key)
            if priority:
                facts.append(item)
            return value
        return None

    w = 'data.win.eventdata.'
    ws = 'data.win.system.'
    event_id = text(f.get(ws+'eventID', ''))
    channel = text(f.get(ws+'channel', ''))
    rule = s.get('rule') or {}
    rule_groups = [text(x).strip() for x in rule.get('groups', [])]
    family = 'Event'
    decoder = text(f.get('decoder.name', ''))
    rgroup = ' '.join(rule_groups).lower()
    observations = []
    gaps = []
    guidance = []

    host = text(f.get('agent.name') or f.get(ws+'computer') or f.get('manager.name'))
    t = s.get('timestamp') or s.get('@timestamp') or ''
    image = add('Process', 'Executable', w+'image', w+'newProcessName', w+'sourceImage', 'data.audit.exe', 'data.exe', 'data.process.name', 'process.executable', priority=True)
    command = add('Process', 'Command line', w+'commandLine', w+'processCommandLine', 'data.audit.command', 'data.command', 'process.command_line', priority=True, kind='code')
    add('Process', 'Process ID', w+'processId', w+'newProcessId', 'data.audit.pid', 'data.pid', 'process.pid')
    add('Process', 'Process GUID', w+'processGuid', 'process.entity_id')
    add('Process', 'Parent executable', w+'parentImage', w+'parentProcessName', 'process.parent.executable', priority=True)
    add('Process', 'Parent command line', w+'parentCommandLine', 'process.parent.command_line', kind='code')
    add('Process', 'Parent process ID', w+'parentProcessId', 'data.audit.ppid', 'process.ppid')
    add('Process', 'Parent process GUID', w+'parentProcessGuid', 'process.parent.entity_id')
    add('Process', 'Working directory', w+'currentDirectory', 'process.working_directory')
    add('Process', 'Integrity level', w+'integrityLevel')
    user = add('Identity', 'User', w+'user', w+'targetUserName', w+'subjectUserName', 'data.dstuser', 'data.srcuser', 'data.user', 'data.audit.auid', 'user.name', priority=True)
    add('Identity', 'Target domain', w+'targetDomainName')
    add('Identity', 'Initiating user', w+'subjectUserName', 'data.srcuser')
    add('Identity', 'Initiating domain', w+'subjectDomainName')
    add('Identity', 'User SID', w+'targetUserSid', w+'subjectUserSid')
    add('Identity', 'Logon ID', w+'targetLogonId', w+'subjectLogonId', w+'logonId')
    add('Identity', 'Logon GUID', w+'logonGuid')
    add('Identity', 'Audit login UID', 'data.audit.auid')
    add('Identity', 'Effective UID', 'data.audit.euid')
    add('Identity', 'Audit session', 'data.audit.session')
    add('Identity', 'Cloud identity', 'data.aws.userIdentity.arn', 'data.aws.userIdentity.userName', 'data.azure.caller', 'data.office365.UserId', 'data.gcp.protoPayload.authenticationInfo.principalEmail', 'data.github.actor', priority=True)
    add('Activity', 'Recorded action', 'data.action', 'data.operation', 'data.aws.eventName', 'data.office365.Operation', 'data.gcp.protoPayload.methodName', 'event.action', priority=True)
    add('Activity', 'Target resource', 'data.office365.ObjectId', 'data.aws.requestParameters.roleArn', 'data.azure.resourceId', 'data.gcp.protoPayload.resourceName', 'data.github.repo', priority=True)
    add('Activity', 'Result', 'data.status', 'data.result', 'data.outcome', 'data.aws.errorCode', 'data.office365.ResultStatus', 'event.outcome', priority=True)
    add('Activity', 'Reason', 'data.reason', 'data.aws.errorMessage', 'data.gcp.protoPayload.status.message', priority=True)

    file_path = add('File', 'File path', 'syscheck.path', w+'targetFilename', 'data.file', 'data.path', 'file.path', priority=True)
    add('Activity', 'Target object', w+'objectName', 'data.object', priority=True)
    add('File', 'Image loaded', w+'imageLoaded', priority=True)
    add('File', 'File hashes', w+'hashes', 'data.hash', 'file.hash.sha256', priority=True)
    add('File', 'File signature', w+'signature')
    add('File', 'Signature status', w+'signatureStatus')
    add('File', 'Signed', w+'signed')

    src = add('Network', 'Source IP', 'data.src_ip', 'data.srcip', w+'sourceIp', w+'ipAddress', 'data.aws.sourceIPAddress', 'data.office365.ClientIP', 'source.ip', priority=True)
    dst = add('Network', 'Destination IP', 'data.dest_ip', 'data.dstip', w+'destinationIp', 'destination.ip', priority=True)
    add('Network', 'Source port', 'data.src_port', 'data.srcport', w+'sourcePort', w+'ipPort', 'source.port')
    add('Network', 'Destination port', 'data.dest_port', 'data.dstport', w+'destinationPort', 'destination.port', priority=True)
    add('Network', 'Protocol', 'data.proto', 'data.protocol', w+'protocol', 'network.transport')
    add('Network', 'Connection direction', w+'initiated', 'network.direction')
    add('Network', 'Destination hostname', w+'destinationHostname', 'data.http.hostname', 'data.tls.sni', priority=True)
    add('Network', 'Community ID', 'data.community_id', 'network.community_id')
    add('Network', 'Sensor flow ID', 'data.flow_id')
    add('Network', 'HTTP method', 'data.http.http_method')
    add('Network', 'HTTP URL', 'data.http.url', 'url.full', priority=True)
    add('Network', 'HTTP user agent', 'data.http.http_user_agent', 'user_agent.original')
    add('Network', 'DNS query', w+'queryName', 'data.dns.rrname', 'data.dns.query.rrname', 'dns.question.name', priority=True)
    add('Network', 'DNS results', w+'queryResults', 'data.dns.answers')
    add('Network', 'TLS subject', 'data.tls.subject')
    add('Network', 'TLS issuer', 'data.tls.issuerdn')
    add('Network', 'TLS certificate fingerprint', 'data.tls.fingerprint')

    # Sources have distinct semantics; these adapters are selected by schema,
    # provider and event IDs, never by the few alerts present at installation.
    script = add('Script', 'Script content', w+'scriptBlockText', 'powershell.file.script_block_text', priority=True, kind='code')
    add('Script', 'Script path', w+'path', 'powershell.file.script_block_id', priority=True)
    add('Script', 'Script block ID', w+'scriptBlockId')
    add('Script', 'Fragment number', w+'messageNumber')
    add('Script', 'Total fragments', w+'messageTotal')
    if script or 'powershell' in channel.lower():
        family = 'PowerShell'
        if script:
            observations.append('PowerShell recorded the script content shown below. The record establishes the logged content; it does not establish that every statement completed successfully.')
            if re.search(r'(?i)FromBase64String\s*\(', text(script)):
                observations.append('The recorded script contains a FromBase64String call. This is a decoding operation used by both legitimate administration and malicious scripts; intent requires the surrounding evidence.')
            if not command:
                gaps.append('The script-block event does not contain the original PowerShell launch command. Related process events may supply it.')
            if number(f.get(w+'messageTotal'),1) > 1:
                gaps.append('This script was logged in fragments. The investigation checks whether all fragments are available before displaying a reconstructed script.')
        guidance += ['Review the complete script and any decoded literals before judging intent.', 'Follow the PowerShell host process, parent command, file writes and outbound connections in the surrounding timeline.']
    elif s.get('syscheck'):
        family = 'File integrity'
        action = add('File change', 'Recorded change', 'syscheck.event', priority=True)
        add('File change', 'Changed attributes', 'syscheck.changed_attributes', priority=True)
        for attr, title in [('sha256', 'SHA-256'), ('sha1', 'SHA-1'), ('md5', 'MD5'), ('size', 'Size'), ('mtime', 'Modified time'), ('perm', 'Permissions'), ('uname', 'Owner'), ('gname', 'Group'), ('inode', 'Inode')]:
            add('Before', title, 'syscheck.'+attr+'_before')
            add('After', title, 'syscheck.'+attr+'_after')
        add('File change', 'Recorded content difference', 'syscheck.diff', priority=True, kind='code')
        observations.append(f'File integrity monitoring recorded {text(action) or "a change"} for {text(file_path) or "the recorded file"}. The before and after values are presented separately.')
        if not any(k.startswith('syscheck.audit') for k in f):
            gaps.append('This file-integrity record does not identify the process responsible for the change.')
        guidance += ['Compare the changed attributes and hashes with an expected deployment or package change.', 'Use nearby process and audit events to investigate who changed the file; a time overlap alone does not prove attribution.']
    elif f.get('data.sca.policy') or decoder == 'sca' or 'sca' in rule_groups:
        family = 'Configuration assessment'
        for key, title in [('policy', 'Policy'), ('check.title', 'Check'), ('check.description', 'Check description'), ('check.result', 'Result'), ('check.rationale', 'Rationale'), ('check.remediation', 'Remediation guidance'), ('check.condition', 'Condition'), ('check.command', 'Check command'), ('check.file', 'Checked file'), ('check.directory', 'Checked directory'), ('check.registry', 'Checked registry'), ('check.reason', 'Check reason'), ('check.references', 'References')]:
            add('Configuration check', title, 'data.sca.'+key, priority=key in ('check.title', 'check.result', 'check.rationale', 'check.remediation'))
        observations.append('A configuration assessment reported the check result below. A failed hardening check is a configuration finding and does not, by itself, demonstrate an intrusion.')
        guidance += ['Check the policy rationale and applicability to this lab host before changing configuration.', 'Verify the actual setting and account for deliberately vulnerable lab systems.']
    elif 'vulnerability' in rgroup or any(k.startswith('data.vulnerability.') for k in f):
        family = 'Vulnerability'
        for key, title in [('cve','CVE'),('title','Finding'),('severity','Vendor severity'),('package.name','Package'),('package.version','Installed version'),('package.condition','Affected version condition'),('rationale','Rationale'),('reference','Reference'),('status','Status')]:
            add('Vulnerability', title, 'data.vulnerability.'+key, priority=True)
        observations.append('The vulnerability detector reported affected software metadata. Confirm package provenance, vendor backports and exposure before deciding remediation priority.')
        guidance += ['Verify the installed package and vendor advisory, including backported fixes.', 'Check whether the vulnerable feature is reachable and plan a tested update.']
    elif f.get('data.event_type') or 'suricata' in rgroup:
        family = 'Network detection' if f.get('data.alert.signature') else 'Network activity'
        for key, title in [('signature','Sensor signature'),('signature_id','Signature ID'),('category','Signature category'),('severity','Sensor severity'),('action','Sensor action')]:
            add('Sensor detection', title, 'data.alert.'+key, priority=True)
        add('Network', 'Application protocol', 'data.app_proto')
        add('Network', 'Bytes to server', 'data.flow.bytes_toserver')
        add('Network', 'Bytes to client', 'data.flow.bytes_toclient')
        observations.append(f'The network sensor recorded {text(f.get("data.event_type")) or "an alert"} traffic from {text(src) or "an unrecorded source"} to {text(dst) or "an unrecorded destination"}. The collector host is not necessarily the affected endpoint.')
        guidance += ['Inspect the signature, URL, DNS and TLS evidence that is present.', 'Correlate Community ID or endpoint addresses with host network events. A passive signature is not proof that an exploit succeeded.']
    elif f.get('data.audit.type'):
        family = 'Linux audit'
        add('Linux audit', 'Audit record type', 'data.audit.type', priority=True)
        add('Linux audit', 'Audit event ID', 'data.audit.id')
        add('Linux audit', 'System call', 'data.audit.syscall')
        add('Linux audit', 'System call result', 'data.audit.success', 'data.audit.exit', priority=True)
        add('Linux audit', 'Audit key', 'data.audit.key')
        add('Linux audit', 'Arguments', 'data.audit.execve', 'data.audit.proctitle', kind='code', priority=True)
        for key in ('data.audit.command','data.audit.proctitle'):
            encoded=text(f.get(key))
            if re.fullmatch(r'[0-9A-Fa-f]{4,131072}',encoded) and len(encoded)%2==0:
                try:
                    decoded=bytes.fromhex(encoded).decode('utf-8').replace('\x00',' ')
                    if all(ord(c)>=32 or c in '\t\r\n' for c in decoded):
                        item={'label':'Decoded audit command','value':decoded,'field':key,'kind':'code','transformation':'Hex-decoded UTF-8; NUL separators displayed as spaces'}
                        groups['Linux audit'].insert(0,item);facts.insert(0,item)
                except (ValueError,UnicodeError):pass
        observations.append('Linux audit recorded the executable, command and audit identity shown below where supplied. Records with the same audit event ID belong to one audited operation.')
        gaps.append('Linux PIDs can be reused. This console does not infer a persistent process identity from a PID alone.')
        guidance += ['Group records by audit event ID and host to inspect the complete operation.', 'Distinguish the login UID from the effective UID and check session and parent information.']
    elif any(k.startswith('data.docker.') for k in f) or f.get('data.Type') == 'container' or f.get('data.integration')=='redsec_docker' or 'docker' in decoder:
        family = 'Container'
        for key, title in [('Action','Action'), ('id','Container ID'), ('Actor.ID','Actor ID'), ('Actor.Attributes.name','Container name'), ('Actor.Attributes.image','Image'), ('privileged','Privileged'), ('user','Container user'), ('network_mode','Network mode')]:
            add('Container', title, 'data.'+key, 'data.docker.'+key, priority=True)
        for key,title in [('action','Lifecycle action'),('actor_id','Container ID'),('name','Container name'),('image','Image'),('container_user','Container execution user'),('exit_code','Exit code'),('signal','Signal')]:
            add('Container',title,'data.'+key,priority=True)
        add('Container','Container image','data.container.image.name','data.docker.image.name','container.image.name',priority=True)
        for item in groups['Container']:
            if item['label']=='Image':item['label']='Container image'
        # Human names and image tags lead summaries; IDs remain provenance.
        priority={'Container image':0,'Container name':1,'Lifecycle action':2,'Action':3}
        facts.sort(key=lambda item:priority.get(item['label'],10))
        container_image=next((text(i['value']) for i in groups['Container'] if i['label']=='Container image'),'')
        container_name=next((text(i['value']) for i in groups['Container'] if i['label']=='Container name'),'')
        if not container_image:gaps.append('An image name was not recorded in this event. Container IDs are retained; no historical image name is guessed.')
        observations.append('The container runtime recorded the lifecycle action below'+(' for image '+container_image if container_image else '')+('. Container name: '+container_name if container_name else '')+'.')
        guidance += ['Inspect the container image, execution identity, privileges and lifecycle action.', 'Compare with expected deployments and follow host process and network evidence.']
    elif event_id in ('4688','4689'):
        family='Process creation' if event_id=='4688' else 'Process termination'
        add('Process','Token elevation type',w+'tokenElevationType')
        add('Process','Mandatory integrity label',w+'mandatoryLabel')
        observations.append('Windows Security auditing recorded '+('a new process' if event_id=='4688' else 'a process termination')+'. The executable, initiating identity and command are displayed where recorded.')
        gaps.append('Security-audit PIDs alone do not provide a persistent process identity. GUID-backed Sysmon records are needed to establish the process tree reliably.')
        guidance += ['Review the executable, parent and command against the initiating account and logon session.', 'Find the corresponding Sysmon creation event and follow its process GUID where available.']
    elif event_id in ('4720','4722','4723','4724','4725','4726','4727','4728','4729','4730','4731','4732','4733','4734','4738','4740','4741','4742','4743','4756','4757','4767') or decoder in ('useradd','groupadd','usermod','userdel','groupdel'):
        family='Account or group change'
        for key,title in [('memberName','Changed member'),('memberSid','Member SID'),('samAccountName','Account name'),('userPrincipalName','User principal name'),('privilegeList','Privileges'),('newUacValue','New account-control value'),('oldUacValue','Previous account-control value'),('callerComputerName','Caller computer')]:
            add('Account change',title,w+key,priority=True)
        for key,title in [('uid','UID'),('gid','GID'),('shell','Login shell'),('home','Home directory')]:
            add('Account change',title,'data.'+key,priority=True)
        operations={'4720':'Account created','4722':'Account enabled','4725':'Account disabled','4726':'Account deleted','4728':'Member added to a global group','4732':'Member added to a local group','4756':'Member added to a universal group','4738':'Account changed','4740':'Account locked out','4741':'Computer account created'}
        observations.append(operations.get(event_id,'The identity source recorded an account or group operation')+'. The target identity and initiating identity are distinct evidence fields.')
        guidance += ['Verify the initiating administrator, target account, changed membership and privileges.', 'Check whether subsequent logons or process activity used the changed identity.']
    elif event_id in ('4624','4625','4634','4647','4648','4672','4768','4769','4771','4776') or any(x in rgroup for x in ('authentication','sshd','pam','sudo')):
        family = 'Authentication'
        logon = add('Authentication', 'Logon type', w+'logonType', priority=True)
        meanings = {'2':'Interactive local logon','3':'Network logon','4':'Batch logon','5':'Service logon','7':'Unlock','8':'Network cleartext logon','9':'New credentials','10':'Remote interactive logon','11':'Cached interactive logon'}
        if text(logon) in meanings:
            observations.append('Windows logon type '+text(logon)+' means '+meanings[text(logon)]+'.')
        add('Authentication', 'Authentication package', w+'authenticationPackageName', w+'packageName')
        add('Authentication', 'Workstation', w+'workstationName', w+'workstation')
        add('Authentication', 'Status code', w+'status', 'data.status', priority=True)
        add('Authentication', 'Substatus code', w+'subStatus')
        add('Authentication', 'Failure reason', w+'failureReason', 'data.reason', priority=True)
        add('Authentication', 'Service name', w+'serviceName')
        observations.append({'4624':'Windows recorded a successful logon.', '4625':'Windows recorded a failed logon.', '4648':'Windows recorded an attempt using explicit credentials.', '4672':'Windows recorded special privileges assigned to a logon.', '4768':'The domain controller recorded a Kerberos ticket-granting ticket request.', '4769':'The domain controller recorded a Kerberos service-ticket request.'}.get(event_id, 'The authentication source recorded the identity and result below.'))
        guidance += ['Check the source, account, logon type and result against expected activity.', 'Follow matching logon IDs on the same host and subsequent process activity; do not join common account names as proof of lateral movement.']
    elif event_id in ('12','13','14') and 'sysmon' in channel.lower():
        family = 'Registry'
        add('Registry', 'Registry target', w+'targetObject', priority=True)
        add('Registry', 'Recorded value', w+'details', priority=True, kind='code')
        add('Registry', 'New name', w+'newName', priority=True)
        add('Registry', 'Registry operation', w+'eventType')
        observations.append('Sysmon recorded the registry operation and value shown below, attributed to the recorded process GUID when present.')
        guidance += ['Inspect the actual key and value, then follow the responsible process and its parent.', 'Check whether this change establishes persistence or matches an approved application change.']
    elif event_id in ('19','20','21') and 'sysmon' in channel.lower() or 'wmi' in channel.lower():
        family = 'WMI'
        for key in ['operation','eventNamespace','name','query','type','destination','consumer','filter','clientProcessId']:
            add('WMI', label(key), w+key, priority=True, kind='code' if key in ('query','destination') else 'text')
        observations.append('Windows recorded the WMI operation or subscription details below. Review the actual filter, consumer and destination together when they are available.')
        guidance += ['Inspect the WMI query or consumer destination and the creating identity.', 'Follow the client process and related process creation events.']
    elif event_id in ('4697','7045','4698','4702','4699') or 'taskscheduler' in channel.lower() or 'winrm' in channel.lower():
        family = 'Remote management' if 'winrm' in channel.lower() else 'Service or scheduled task'
        for key, title in [('taskName','Task name'),('taskContent','Task definition'),('taskContentNew','New task definition'),('serviceName','Service name'),('imagePath','Service command'),('serviceFileName','Service executable'),('accountName','Service account'),('serviceStartType','Start type'),('shellId','WinRM shell ID'),('connection','Connection')]:
            add('Management activity', title, w+key, priority=True, kind='code' if key in ('taskContent','taskContentNew','imagePath','serviceFileName') else 'text')
        task_xml=text(f.get(w+'taskContentNew') or f.get(w+'taskContent'))
        if task_xml and len(task_xml)<131072 and not re.search(r'(?i)<!\s*(?:DOCTYPE|ENTITY)',task_xml):
            try:
                root=ET.fromstring(task_xml)
                names={'Command':'Task executable','Arguments':'Task arguments','WorkingDirectory':'Task working directory','UserId':'Task execution identity','RunLevel':'Task privilege level','LogonType':'Task logon method'}
                for node in root.iter():
                    key=node.tag.rsplit('}',1)[-1]
                    if key in names and node.text:
                        item={'label':names[key],'value':node.text,'field':w+('taskContentNew' if f.get(w+'taskContentNew') else 'taskContent'),'kind':'code' if key in ('Command','Arguments') else 'text','transformation':'Extracted XML '+key}
                        groups['Task actions'].append(item);facts.append(item)
            except ET.ParseError:gaps.append('The task definition could not be parsed as XML. The recorded definition remains visible.')
        guidance += ['Inspect the complete task or service command, execution account and initiating user.', 'Follow management-session identifiers and process evidence on the destination host.']
    elif 'defender' in channel.lower() or 'defender' in rgroup:
        family = 'Endpoint protection'
        for key,title in [('threatName','Threat name'),('path','Affected path'),('processName','Process'),('actionName','Action'),('detectionUser','Detection user'),('errorDescription','Error')]:
            add('Protection detection',title,w+key,priority=True)
        guidance += ['Read the protection action and result before assuming the threat was blocked.', 'Inspect affected files, execution history and related network activity.']
    elif event_id and 'sysmon' in channel.lower():
        family = { '1':'Process creation', '3':'Network connection', '7':'Image load', '8':'Remote thread', '10':'Process access', '11':'File creation', '15':'File stream', '17':'Named pipe', '18':'Named pipe', '22':'DNS', '23':'File deletion', '24':'Clipboard', '25':'Process tampering', '26':'File deletion' }.get(event_id, 'Sysmon activity')
        for key,title in [('sourceImage','Source executable'),('targetImage','Target executable'),('sourceProcessGUID','Source process GUID'),('targetProcessGUID','Target process GUID'),('grantedAccess','Granted access'),('pipeName','Pipe name'),('contents','Recorded content'),('sourceThreadId','Source thread ID'),('startAddress','Thread start address')]:
            add('Endpoint activity',title,w+key,priority=True)
        observations.append(f'Sysmon recorded {family.lower()} with the process, object and activity evidence below. The event records an observation; the detection title supplies the rule classification.')
        guidance += ['Follow the process GUID and parent chain to identify the originating execution.', 'Review related file, registry, authentication and network events in the timeline.']
    elif decoder in ('dpkg-decoder','yum','rpm') or any(k.startswith('data.package') for k in f):
        family='Software package'
        for key,title in [('package','Package'),('version','Recorded version'),('arch','Architecture'),('dpkg_status','Package operation')]:
            add('Software package',title,'data.'+key,priority=True)
        observations.append('The package manager recorded the package operation and version below. This is software-change evidence; compare it with expected maintenance.')
        guidance += ['Verify the package origin, operation and version against an approved installation or update.', 'Review adjacent administrator activity and service changes when the operation is unexpected.']
    elif decoder=='systemd':
        family='Service health'
        add('Service health','Recorded service message','full_log',priority=True,kind='code')
        observations.append('The service manager recorded the lifecycle or failure message below. A service-state change is not, by itself, evidence of compromise.')
        guidance += ['Identify the service, recorded state and error from the message.', 'Compare with maintenance and nearby administrator activity; inspect its logs before restarting it.']
    elif decoder=='ossec' or 'ossec' in rule_groups:
        family='Monitoring health'
        add('Monitoring health','Monitoring message','full_log',priority=True,kind='code')
        observations.append('Wazuh recorded a monitoring or agent-health condition. Review the exact message and affected host before treating it as endpoint threat activity.')
        guidance += ['Check agent connectivity, collection freshness and any queue or configuration errors.', 'Resolve collection problems before drawing conclusions from missing detections.']
    else:
        for prefix,name in [('data.office365.','Microsoft 365'),('data.aws.','AWS'),('data.gcp.','Google Cloud'),('data.azure.','Azure'),('data.github.','GitHub'),('data.virustotal.','Threat intelligence')]:
            if any(k.startswith(prefix) for k in f):
                family=name
                break
        observations.append('The source recorded the activity below and Wazuh classified it using the displayed rule. Only supplied fields are presented as facts.')
        guidance += ['Review the rule conditions and the recorded object, action, actor and result.', 'Use the timeline and source references to verify related activity before assigning a disposition.']

    add('Source record', 'Event ID', ws+'eventID', 'event.code')
    add('Source record', 'Provider', ws+'providerName', 'event.provider')
    add('Source record', 'Channel', ws+'channel')
    add('Source record', 'Computer', ws+'computer')
    add('Source record', 'Provider message', ws+'message', 'data.message', 'message', priority=not facts, kind='code')
    # Meaningfully render ALL remaining decoded fields, including future decoders.
    for key,value in f.items():
        if key not in used and key.startswith(('data.', 'syscheck.')) and value is not None:
            section='Additional '+family.lower()+' evidence'
            groups[section].append({'label':label(re.sub(r'^(data\.win\.(eventdata|system)\.|data\.|syscheck\.)','',key)), 'value':value,'field':key,'kind':'code' if len(text(value))>200 else 'text'})
    if not facts:
        for items in groups.values():
            facts.extend(items[:4])
            if facts:break
    if not facts:
        add('Source record','Recorded log','full_log',priority=True,kind='code')
    if not facts:
        gaps.append('The indexed record contains no decoded event details or original log content.')
    if family == 'Event':
        gaps.append('No specialized source adapter matched. All decoded fields remain visible, but deeper source-specific interpretation is unavailable.')
    if not observations:
        observations.append('The source recorded the activity and affected objects shown below. The rule conditions explain why Wazuh raised this alert.')
    # Structured subject is used both in the queue and on the first screen.
    subject = next((text(x['value']) for x in facts if x['label'] in ('File path','Registry target','Task name','Service name','Script path','Check','CVE','Sensor signature')), '')
    subject = subject or text(image or command or user or src) or next((text(x['value']) for x in facts), '')
    if family=='Container':
        subject=(container_image+(' · '+container_name if container_name else '')) if container_image else container_name or 'Container image not recorded'
    if script and not subject:
        subject='PowerShell script block '+text(f.get(w+'scriptBlockId',''))
    if script and family=='PowerShell':
        paths=re.findall(r"(?i)(?:[a-z]:\\{1,2}|/(?:tmp|var|home)/)[^\r\n'\";<>|]{1,240}",text(script))
        if paths:
            groups['Script'].insert(0, {'label':'Path literal in script','value':paths[0], 'field':w+'scriptBlockText','kind':'text'})
            subject=paths[0]
    p_guid=guid(f.get(w+'processGuid') or f.get(w+'sourceProcessGUID') or f.get(w+'sourceProcessGuid') or f.get('process.entity_id'))
    parent_guid=guid(f.get(w+'parentProcessGuid') or f.get('process.parent.entity_id'))
    identity_parts=[s.get('manager',{}).get('name'),f.get('agent.id'),host,s.get('id'),t] if s.get('id') else [host,t,rule.get('id'),s.get('full_log'),s.get('data'),s.get('syscheck')]
    fingerprint=hashlib.sha256(json.dumps(identity_parts,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    ref={'index':hit.get('_index',''), 'id':hit.get('_id','')}
    return {'key':fingerprint,'ref':ref,'time':t,'host':host,'agent_id':text(f.get('agent.id')),'agent_ip':text(f.get('agent.ip')),'family':family,'title':text(rule.get('description')) or family,'level':number(rule.get('level')), 'rule_id':text(rule.get('id')),'rule_groups':rule_groups,'mitre':rule.get('mitre',{}),'event_id':event_id,'channel':channel,'subject':subject[:1000], 'facts':facts,'evidence':dict(groups),'observations':observations,'gaps':gaps,'guidance':guidance,'identity':{'user':text(user),'process_guid':p_guid,'process_guid_raw':text(f.get(w+'processGuid') or f.get(w+'sourceProcessGUID') or f.get(w+'sourceProcessGuid')),'parent_guid':parent_guid,'parent_guid_raw':text(f.get(w+'parentProcessGuid')),'pid':text(f.get(w+'processId') or f.get('data.audit.pid')),'image':text(image),'parent_image':text(f.get(w+'parentImage')),'command':text(command),'source_ip':text(src),'destination_ip':text(dst),'source_port':text(f.get('data.src_port') or f.get('data.srcport') or f.get(w+'sourcePort') or f.get(w+'ipPort') or f.get('source.port')),'destination_port':text(f.get('data.dest_port') or f.get('data.dstport') or f.get(w+'destinationPort') or f.get('destination.port')),'protocol':text(f.get('data.proto') or f.get(w+'protocol') or f.get('network.transport')).lower(),'community_id':text(f.get('data.community_id')),'flow_id':text(f.get('data.flow_id')),'logon_id':text(f.get(w+'logonId') or f.get(w+'targetLogonId') or f.get(w+'subjectLogonId')),'script_block_id':text(f.get(w+'scriptBlockId')),'audit_id':text(f.get('data.audit.id')),'logon_guid':guid(f.get(w+'logonGuid')),'logon_type':text(f.get(w+'logonType')),'initiated':text(f.get(w+'initiated')).lower(),'observed_time':text(f.get(w+'utcTime') or f.get(ws+'systemTime') or f.get('data.timestamp')),'flow_start':text(f.get('data.flow.start')),'flow_end':text(f.get('data.flow.end'))}, 'is_alert':bool(rule),'sort':hit.get('sort')}


def decoded_literals(event):
    """Bounded, static literal decoding only; no eval, shell, decompression or I/O."""
    results=[]
    for section in event['evidence'].values():
        for item in section:
            if item['label'] not in ('Script content','Command line'):continue
            value=text(item['value'])[:262144]
            matches=[(m.group(1),'utf-8','FromBase64String literal') for m in re.finditer(r'''(?i)FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=\r\n]{4,65536})['"]\s*\)''',value)]
            matches += [(m.group(1),'utf-16-le','EncodedCommand argument') for m in re.finditer(r'(?i)-(?:encodedcommand|enc|ec)\s+([A-Za-z0-9+/=]{4,65536})',value)]
            for literal,encoding,origin in matches[:8]:
                try:
                    raw=base64.b64decode(re.sub(r'\s','',literal),validate=True)
                    decoded=raw.decode(encoding)
                    if any(ord(c)<9 or 13<ord(c)<32 for c in decoded):raise ValueError()
                    results.append({'origin':origin,'field':item['field'],'encoding':encoding,'content':decoded,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'notice':'Statically decoded literal. Its presence does not prove the decoded content executed.'})
                except (ValueError,UnicodeError):
                    results.append({'origin':origin,'field':item['field'],'content':None,'notice':'Literal is not valid text in the expected encoding. Binary content is not executed or rendered.'})
    return results[:8]


def focus_evidence(event,source,rules):
    """Select relevant values from arbitrary installed rule definitions."""
    flat=flatten(source);existing={i['field']:i for rows in event['evidence'].values() for i in rows}
    focus=[];seen=set();explanations=[]
    for definition in rules['rules']:
        for c in definition['conditions']:
            if c['kind'] in ('field','list'):
                name=c.get('name') or c.get('field','');field='data.'+name if name.startswith('win.') or ('data.'+name in flat) else name
                if field in flat:
                    item=existing.get(field,{'field':field,'label':label(name),'value':flat[field],'kind':'text'})|{'referenced_by':definition['id']}
                    if field not in seen:focus.append(item);seen.add(field)
                    plain=re.sub(r'^\(\?i\)','',c['value'])
                    if c['kind']=='list':explanations.append(f'Rule {definition["id"]} uses {item["label"]} for a configured list lookup. Its recorded value is displayed; list membership is not re-evaluated by this console.')
                    elif re.fullmatch(r'[a-zA-Z0-9_ .:/-]{3,100}',plain) and c.get('negate')!='yes' and plain.lower() in text(flat[field]).lower():
                        explanations.append(f'Rule {definition["id"]} references {item["label"]}; the recorded value contains the literal “{plain}”.')
                    else:explanations.append(f'Rule {definition["id"]} evaluates {item["label"]}. The actual recorded value is displayed in the evidence; its '+('negated ' if c.get('negate')=='yes' else '')+'pattern condition is shown in the definition.')
                else:explanations.append(f'Rule {definition["id"]} references {label(name)}, but that field is not present in this indexed record.')
            elif c['kind'] in ('if_matched_sid','if_matched_group','same_field','different_field'):
                explanations.append(f'This rule includes a correlation condition ({c["kind"]}: {c["value"]}). The triggering record alone does not supply the complete matched sequence; review the related timeline.')
        if definition.get('frequency'):explanations.append(f'Rule {definition["id"]} has configured frequency {definition["frequency"]} and timeframe {definition.get("timeframe") or "unspecified"} seconds. These are rule settings, not a replayed event count.')
    for item in event['facts']:
        if item['field'] not in seen:focus.append(item);seen.add(item['field'])
    event['focus']=focus;rules['explanations']=list(dict.fromkeys(explanations))
    return event,rules


def relation(seed,other):
    a,b=seed['identity'],other['identity']
    same_host=seed['host']==other['host']
    for key,title in [('process_guid','Same process GUID'),('script_block_id','Same script block ID'),('audit_id','Same audited operation')]:
        if same_host and a.get(key) and a[key]==b.get(key):return {'basis':title,'strength':'identifier'}
    if same_host and a.get('process_guid') and (a['process_guid']==b.get('parent_guid') or a.get('parent_guid')==b.get('process_guid')):
        return {'basis':'Recorded parent/child GUID','strength':'identifier'}
    if a.get('community_id') and a['community_id']==b.get('community_id'):return {'basis':'Same Community ID; flow association','strength':'flow'}
    if same_host and a.get('flow_id') and a['flow_id']==b.get('flow_id'):return {'basis':'Same sensor flow ID','strength':'flow'}
    if same_host and a.get('logon_id') and a['logon_id'] not in ('0x0','0x3e7','0x3e4','0x3e5') and a['logon_id']==b.get('logon_id'):
        return {'basis':'Same host and logon ID; session association','strength':'session'}
    flow_keys=('source_ip','source_port','destination_ip','destination_port','protocol')
    if all(a.get(k) and b.get(k) for k in flow_keys):
        direct=all(a[k]==b[k] for k in flow_keys)
        reverse=a['source_ip']==b['destination_ip'] and a['destination_ip']==b['source_ip'] and a['source_port']==b['destination_port'] and a['destination_port']==b['source_port'] and a['protocol']==b['protocol']
        if direct or reverse:return {'basis':'Same network tuple in selected window; association candidate','strength':'flow'}
    ip_a={a.get('source_ip'),a.get('destination_ip'),seed.get('agent_ip')}-{None,''}
    ip_b={b.get('source_ip'),b.get('destination_ip'),other.get('agent_ip')}-{None,''}
    if ip_a & ip_b:return {'basis':'Shared endpoint address in selected time window','strength':'context'}
    return {'basis':'Same host in selected time window' if same_host else 'Selected time window','strength':'context'}


def process_graph(events):
    nodes={};edges={};missing=[]
    for e in events:
        identity=e['identity'];pg=identity.get('process_guid')
        if not pg:continue
        key=e['host']+'|'+pg
        n=nodes.setdefault(key,{'id':key,'guid':pg,'host':e['host'],'image':identity.get('image') or 'Process name not recorded','command':identity.get('command'),'observed':False,'events':[],'time':e['time']})
        if e['event_id']=='1':
            if 'sysmon' in e.get('channel','').lower():n.update(image=identity.get('image') or n['image'],command=identity.get('command') or n['command'],observed=True,time=e['time'])
        n['events'].append(e['ref'])
        parent=identity.get('parent_guid')
        if parent and parent!=pg:
            pk=e['host']+'|'+parent
            nodes.setdefault(pk,{'id':pk,'guid':parent,'host':e['host'],'image':identity.get('parent_image') or 'Parent name not recorded','command':'','observed':False,'events':[],'time':''})
            edges[(pk,key)]={'parent':pk,'child':key,'basis':'Parent GUID recorded by source','evidence':e['ref']}
    # A placeholder is explicit, not an invented process-creation event.
    for n in nodes.values():
        if not n['observed']:n['notice']='Creation event not found in the retrieved evidence. Identity or parent reference was recorded by another event.'
    parent_sets=defaultdict(set)
    for edge in edges.values():parent_sets[edge['child']].add(edge['parent'])
    for key,parents in parent_sets.items():
        if len(parents)>1:nodes[key]['notice']='Conflicting parent GUID references were retrieved; ancestry is ambiguous.'
    return {'nodes':list(nodes.values())[:160],'edges':list(edges.values())[:160],'truncated':len(nodes)>160,'conflicting_parents':sum(len(p)>1 for p in parent_sets.values()),'notice':'Edges use recorded process GUIDs scoped to one host. PID-only records remain in the timeline and are not joined into an inferred tree.'}


def script_fragments(seed,events):
    sid=seed['identity'].get('script_block_id')
    if not sid:return None
    parts={};expected=1;refs=[]
    for e in events:
        if e['host']!=seed['host'] or e['identity'].get('script_block_id')!=sid:continue
        fields={item['label']:item for item in e['evidence'].get('Script',[])}
        if 'Script content' not in fields:continue
        try:
            number=int(text(fields.get('Fragment number',{}).get('value',1)))
            expected=max(expected,int(text(fields.get('Total fragments',{}).get('value',1))))
        except ValueError:continue
        parts[number]=text(fields['Script content']['value']);refs.append(e['ref'])
    if not parts:return None
    complete=len(parts)==expected and all(i in parts for i in range(1,expected+1))
    return {'complete':complete,'parts_found':len(parts),'parts_expected':expected,'content':''.join(parts[i] for i in sorted(parts)) if complete else None,'refs':refs}
