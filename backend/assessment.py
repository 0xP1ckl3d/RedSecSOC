"""Deterministic, source-backed interpretation; never changes Wazuh severity."""
import hashlib
import json
import re
from engine import flatten,text

REFERENCES={
 'powershell_policy':{'title':'Microsoft: PowerShell application control','url':'https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control'},
 'compatibility':{'title':'Microsoft: Application compatibility database','url':'https://learn.microsoft.com/en-us/windows/win32/devnotes/application-compatibility-database'},
 'shim_abuse':{'title':'MITRE ATT&CK: Application Shimming','url':'https://attack.mitre.org/techniques/T1546/011/'}
}

def windows_path(value):return re.sub(r'[\\/]+','/',text(value)).lower()
def basename(value):return windows_path(value).rsplit('/',1)[-1]

def assess(event,source):
    f=flatten(source);image=text(f.get('data.win.eventdata.image') or event['identity'].get('image'))
    path=text(f.get('data.win.eventdata.targetFilename') or f.get('syscheck.path') or f.get('file.path'))
    path_field=next((k for k in ('data.win.eventdata.targetFilename','syscheck.path','file.path') if f.get(k)),'data.win.eventdata.targetFilename')
    result={'posture':'Needs investigation' if event['is_alert'] else 'Recorded activity','summary':'The source records the activity below. A detection classification is not a confirmed outcome. Review the affected object, initiating identity and associated events.','basis':[],'caveats':['The original detection level is retained; this assessment does not automatically clear or suppress an alert.'],'references':[],'pattern':None}
    if event['family'] in ('Network activity','Network detection','Network connection'):
        result['summary']='This is an observation of network activity. Protocol, addresses, ports and any sensor signature describe the observed connection; they do not by themselves establish exploitation or successful command and control.'
    elif event['family']=='PowerShell':
        result['summary']='PowerShell recorded the script or command shown below. Encoding and decoding are capabilities used by both administration and malicious activity; determine what the recorded content does and which process initiated it.'
    elif event['family'] in ('File creation','File deletion','File integrity'):
        result['summary']='A file operation was recorded. A suspicious directory or filename is a detection signal; it does not establish that the file is malicious or was executed.'
    # A named file alone is not sufficient to attribute policy testing to a
    # genuine PowerShell host. Require the recorded creator and expected path.
    probe=bool(re.search(r'/temp/__psscriptpolicytest_[^/]+\.(?:ps1|psm1)$',windows_path(path)))
    creator=windows_path(image)
    expected_creator=(creator in ('c:/windows/system32/windowspowershell/v1.0/powershell.exe','c:/windows/syswow64/windowspowershell/v1.0/powershell.exe','c:/windows/system32/wsmprovhost.exe') or bool(re.fullmatch(r'c:/program files/powershell/\d+(?:\.\d+)*/pwsh\.exe',creator)))
    if probe:
        result.update(posture='Compatible with expected behavior' if expected_creator else 'Creator identity requires review',pattern='powershell-policy-probe' if expected_creator else 'policy-probe-name-only')
        result['summary']=('The recorded PowerShell host created a temporary script matching PowerShell application-control policy testing. This is compatible with normal policy checks; the file-path match alone does not substantiate a Critical threat finding.' if expected_creator else 'The target filename resembles a PowerShell application-control policy-test script, but the expected creator path was not verified in this event. The filename alone is insufficient to treat it as normal initialization.')
        result['basis']=[{'field':path_field,'value':path,'meaning':'Temporary policy-test filename pattern'},{'field':'data.win.eventdata.image','value':image or 'Not recorded','meaning':'Recorded creator; file signature and binary identity are not verified here'}]
        result['caveats']+=['A filename and expected executable path can be imitated. Inspect the creator signature/hash, parent process and full command line. Policy checks can also occur inside a malicious remote session.']
        result['references']=[REFERENCES['powershell_policy']]
    elif basename(image)=='sdbinst.exe':
        expected=creator in ('c:/windows/system32/sdbinst.exe','c:/windows/syswow64/sdbinst.exe')
        result.update(posture='Dual-use utility: review context' if expected else 'Unexpected utility location',pattern='application-compatibility-database')
        result['summary']='The recorded image is named sdbinst.exe, the Windows application-compatibility database installer. Compatibility databases can be legitimate and can also be abused. Determine which database, command, parent and user are recorded; this event alone does not establish persistence or successful installation.'
        result['basis']=[{'field':'data.win.eventdata.image','value':image,'meaning':'Expected Windows path' if expected else 'Outside the expected System32/SysWOW64 location'},{'field':'data.win.eventdata.commandLine','value':event['identity'].get('command') or 'Not recorded','meaning':'Recorded arguments; installation outcome is not inferred'}]
        result['caveats']+=['A trusted-looking path does not verify binary authenticity. Check recorded hashes/signatures and the referenced .sdb file. Repeated events are occurrences, not proof of one attack or known-benign activity.']
        result['references']=[REFERENCES['compatibility'],REFERENCES['shim_abuse']]
    event['assessment']=result
    return event

def grouping_signature(event,source):
    """Only group material equivalents; do not erase commands or principals."""
    f=flatten(source);i=event['identity'];a=event.get('assessment',{})
    path=f.get('data.win.eventdata.targetFilename') or f.get('syscheck.path') or f.get('file.path') or ''
    if a.get('pattern')=='powershell-policy-probe':path=re.sub(r'__psscriptpolicytest_[^/]+\.(?:ps1|psm1)$','__PSScriptPolicyTest_<generated>.ps1',windows_path(path))
    material={'rule':event['rule_id'],'family':event['family'],'image':windows_path(i.get('image')),'command':i.get('command','').strip(),'parent_image':windows_path(i.get('parent_image')),'user':i.get('user',''),'object':text(path),'hashes':text(f.get('data.win.eventdata.hashes') or f.get('syscheck.sha256_after') or f.get('file.hash.sha256')),'action':text(f.get('data.action') or f.get('syscheck.event') or f.get('data.win.eventdata.eventType')),'network':{k:i.get(k) for k in ('destination_ip','destination_port','protocol')},'container_image':text(f.get('data.image') or f.get('data.docker.Actor.Attributes.image'))}
    if not any((material['image'],material['object'],material['command'],material['container_image'])):
        # Unknown families retain their decoded content in the signature rather
        # than collapsing unrelated records under one rule ID.
        material['decoded_content']=source.get('data',{})
    material['parent_command']=text(f.get('data.win.eventdata.parentCommandLine'))
    material['script_digest']=hashlib.sha256(text(f.get('data.win.eventdata.scriptBlockText')).encode()).hexdigest() if f.get('data.win.eventdata.scriptBlockText') else None
    material['sensor_signature']=text(f.get('data.alert.signature_id'))
    material['container_name']=text(f.get('data.name') or f.get('data.docker.Actor.Attributes.name'))
    digest=hashlib.sha256(json.dumps(material,sort_keys=True,ensure_ascii=False).encode()).hexdigest()
    return digest,material

def group_events(pairs,decisions):
    groups={}
    for event,source in pairs:
        key,material=grouping_signature(event,source)
        g=groups.setdefault(key,{'key':key,'title':event['assessment'].get('pattern')=='application-compatibility-database' and 'Application compatibility database activity' or event['title'],'rule_id':event['rule_id'],'level':event['level'],'material':material,'assessment':event['assessment'],'count':0,'hosts':set(),'first':event['time'],'last':event['time'],'events':[],'decision':decisions.get(key)})
        g['count']+=1;g['hosts'].add(event['host']);g['first']=min(g['first'],event['time']);g['last']=max(g['last'],event['time']);g['level']=max(g['level'],event['level'])
        if len(g['events'])<50:g['events'].append(event)
    for g in groups.values():g['hosts']=sorted(g['hosts'])
    return sorted(groups.values(),key=lambda g:(g['decision'] is not None and g['decision']['classification']=='Expected recurrence',-g['level'],-g['count'],g['key']))
