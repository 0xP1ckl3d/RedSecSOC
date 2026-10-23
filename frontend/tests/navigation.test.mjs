// Component rendering only: no browser, browser driver, or network connection.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {rolldown} from 'rolldown';
import React from 'react';
import {create,act} from 'react-test-renderer';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const folder=await fs.mkdtemp(path.join(root,'node_modules','.navigation-test-'));
const output=path.join(folder,'App.mjs');
const bundle=await rolldown({input:path.join(root,'src/App.jsx'),platform:'node',external:['react','react-dom/client','lucide-react'],plugins:[{name:'ignore-test-css',resolveId(source){if(source.endsWith('.css'))return {id:source,external:true}},transform(code,id){if(id.endsWith('App.jsx'))return code.replace("import './style.css';",'')}}]});
await bundle.write({file:output,format:'esm'});await bundle.close();
const {default:App}=await import(pathToFileURL(output).href);
const patternsOutput=path.join(folder,'Patterns.mjs');
const patternsBundle=await rolldown({input:path.join(root,'src/Patterns.jsx'),platform:'node',external:['react','react-dom/client','lucide-react']});
await patternsBundle.write({file:patternsOutput,format:'esm'});await patternsBundle.close();
const {NetworkPatterns}=await import(pathToFileURL(patternsOutput).href);
const text=node=>typeof node==='string'?node:(node.children||[]).map(text).join('');
const event={key:'one',ref:{index:'wazuh-alerts-test',id:'one'},time:'2026-10-23T00:00:00Z',host:'EXAMPLE',agent_ip:'192.0.2.10',family:'Network activity',title:'Example event',subject:'Example subject',level:10,rule_id:'100',rule_groups:[],mitre:{},identity:{},facts:[],evidence:{},observations:[],gaps:[],guidance:[],state:{status:'New',assignee:''},is_alert:true};

test('alert and network explorer filters, page, and scroll survive detail navigation',async()=>{
 globalThis.IS_REACT_ACT_ENVIRONMENT=true;
 const calls=[],scrolls=[];
 globalThis.document={documentElement:{dataset:{theme:'dark'}}};
 globalThis.localStorage={setItem(){}};
 globalThis.requestAnimationFrame=fn=>fn();
 globalThis.window={scrollY:475,scrollTo:(x,y)=>scrolls.push(y),addEventListener(){},removeEventListener(){}};
 globalThis.fetch=async (url,options={})=>{
  calls.push(url);let result={};
  if(url==='/api/correlations/preserve'){assert.equal(JSON.parse(options.body).eid,'one');result={case_id:'case-example',preserved:2}}
  else if(url.startsWith('/api/correlations?'))result={candidates:[{id:'candidate',seed:event.ref,title:event.title,subject:event.subject,hosts:['EXAMPLE'],event_keys:['one','two'],edges:[{}],stages:['process','network']}],seeds_reviewed:1,matching_seed_occurrences:1};
  else if(url==='/api/me')result={name:'analyst',role:'analyst',csrf:'unit-test-token'};
  else if(url==='/api/deployment')result={label:'Example deployment',links:{}};
  else if(url.startsWith('/api/dashboard?'))result={active_alerts:1,raw_records:5,alerts:{levels:{buckets:[{key:'Critical',doc_count:1}]},suspicious:{doc_count:0},timeline:{buckets:[]},rules:{buckets:[]},hosts:{buckets:[]}},network:{doc_count:3,types:{buckets:[{key:'dns',doc_count:3}]}},priority_events:[event],policies:{safe:0,suspicious:0},coverage:{registered:1,reporting_agents:1,nonreporting:[],stale_sources:[]}};
  else if(url.startsWith('/api/network-patterns?'))result={patterns:[],talkers:[],total_flow_records:0};
  else if(url.startsWith('/api/alert-groups/550/activity?'))result={items:[],sampled:20,total:4910,partial:true};
  else if(url.startsWith('/api/alert-groups?'))result={total:4910,groups:[{key:'550',rule_id:'550',title:'Integrity checksum changed.',level:7,count:4910,hosts:[{key:'EXAMPLE',doc_count:4910}],objects:[{key:'/etc/example/status',doc_count:4910}],criteria:{rule:'550'},sample_ref:event.ref}],partial:false};
  else if(url.startsWith('/api/queue?'))result={events:[event],total:100,page:0,has_more:true,aggregations:{levels:{buckets:[]}},query_ms:1};
  else if(url.startsWith('/api/alert?'))result={event,rules:{rules:[]},raw:{example:'fixture'},annotations:{notes:[],history:[]}};
  else if(url.startsWith('/api/investigation?'))result={counts:{loaded:2,related_alerts:0},graph:{nodes:[],edges:[]},events:[event,{...event,key:'two',ref:{index:'wazuh-archives-test',id:'two'}}],related_alerts:[],correlation:{selected:{event_keys:['one','two'],hosts:['EXAMPLE'],stages:['process','network'],status:'Candidate'},edges:[{source:'one',target:'two',source_ref:event.ref,target_ref:{index:'wazuh-archives-test',id:'two'},kind:'identifier',basis:'Same host and process GUID',fields:['process_guid'],support:[]}]}};
  return {ok:true,status:200,json:async()=>result};
 };
 let renderer;
 try{
  await act(async()=>{renderer=create(React.createElement(App));await new Promise(setImmediate)});
  const change=async(label,value)=>act(async()=>{renderer.root.findAll(n=>n.type==='input'||n.type==='select').find(n=>n.props['aria-label']===label).props.onChange({target:{value}});await new Promise(setImmediate)});
  const click=async(label)=>act(async()=>{const button=renderer.root.findAllByType('button').find(n=>text(n)===label);assert.ok(button,'Missing button '+label);button.props.onClick();await new Promise(setImmediate)});
  const openAndBack=async()=>{
   await act(async()=>{renderer.root.findAllByType('tr').find(n=>n.props.className?.includes('alert-row')).props.onClick();await new Promise(setImmediate)});
   assert.ok(renderer.root.findAllByType('div').some(n=>n.props.hidden===true));
   await click('Back');assert.equal(scrolls.at(-1),475);
  };
  assert.ok(renderer.root.findAllByType('h1').some(n=>text(n)==='Network & detection overview'));
  assert.ok(renderer.root.findAllByType('button').some(n=>n.props.className==='critical'&&text(n).includes('Critical detections')));
  assert.ok(renderer.root.findAllByType('button').some(n=>n.props.className==='suspicious'&&text(n).includes('Analyst-marked suspicious')));
  // The network panel has its own range; every drill-through uses that range.
  const beforeSlide=calls.filter(u=>u.startsWith('/api/network-patterns?')).length;
  await change('Network trailing window minutes','60');
  assert.equal(calls.filter(u=>u.startsWith('/api/network-patterns?')).length,beforeSlide);
  await act(async()=>{renderer.root.findAllByType('input').find(n=>n.props['aria-label']==='Network trailing window minutes').props.onPointerUp({currentTarget:{value:'60'}});await new Promise(setImmediate)});
  await act(async()=>{await new Promise(r=>setTimeout(r,250))});
  const ranged=new URL('https://example.test'+calls.filter(u=>u.startsWith('/api/network-patterns?')).at(-1));
  assert.equal(new Date(ranged.searchParams.get('end'))-new Date(ranged.searchParams.get('start')),3600000);
  await change('Network range start','2026-10-22T02:30');await change('Network range end','2026-10-22T03:00');
  await act(async()=>{renderer.root.findAllByType('form').find(n=>n.props.className==='exact-window').props.onSubmit({preventDefault(){}});await new Promise(setImmediate)});
  await act(async()=>{await new Promise(r=>setTimeout(r,250))});
  const fixed=new URL('https://example.test'+calls.filter(u=>u.startsWith('/api/network-patterns?')).at(-1));
  assert.equal(fixed.searchParams.get('start'),'2026-10-22T02:30:00.000Z');assert.equal(fixed.searchParams.get('end'),'2026-10-22T03:00:00.000Z');
  await click('Explore network patterns');
  assert.equal(renderer.root.findAllByType('select').find(n=>n.props['aria-label']==='Pattern time window').props.value,'custom');
  assert.ok(calls.filter(u=>u.startsWith('/api/network-patterns?')).at(-1).includes('start=2026-10-22T02%3A30%3A00.000Z'));
  await click('Overview');
  await click('Run evidence correlation');
  await act(async()=>{renderer.root.findAllByType('div').find(n=>n.props.className==='candidate-list').findByType('button').props.onClick();await new Promise(setImmediate)});
  assert.ok(renderer.root.findAllByType('h2').some(n=>text(n)==='Evidence links for this sequence'));
  await click('Preserve linked sequence in one investigation');assert.ok(calls.includes('/api/correlations/preserve'));await click('Back');
  await click('Alert inbox');
  await change('Search alerts and evidence','EXE');
  await act(async()=>{renderer.root.findAllByType('form').find(n=>n.props.className==='search').props.onSubmit({preventDefault(){}});await new Promise(setImmediate)});
  await change('Minimum severity','10');await change('Disposition','Investigating');await change('Filter host','EXAMPLE');await click('Next');
  const before=calls.filter(u=>u.startsWith('/api/queue?')).at(-1);await openAndBack();
  assert.equal(calls.filter(u=>u.startsWith('/api/queue?')).at(-1),before);
  await click('Event explorer');await click('Network logs');
  await act(async()=>{renderer.root.findAllByType('select').find(n=>n.props.children?.some?.(c=>c?.props?.children==='All protocols')).props.onChange({target:{value:'smb'}});await new Promise(setImmediate)});
  await act(async()=>{renderer.root.findAllByType('input').find(n=>n.props.placeholder==='Any port').props.onChange({target:{value:'445'}});await new Promise(setImmediate)});
  await change('Filter host','SENSOR');await click('Next');
  const networkBefore=calls.filter(u=>u.startsWith('/api/queue?')).at(-1);assert.ok(networkBefore.includes('protocol=smb')&&networkBefore.includes('port=445'));
  await openAndBack();assert.equal(calls.filter(u=>u.startsWith('/api/queue?')).at(-1),networkBefore);
  await click('Overview');
  await act(async()=>{renderer.root.findAllByType('button').find(n=>n.props['aria-label']==='Open dns network records').props.onClick();await new Promise(setImmediate)});
  const drill=calls.filter(u=>u.startsWith('/api/queue?')).at(-1);assert.ok(drill.includes('record_type=dns')&&drill.includes('category=network'));
  await openAndBack();assert.equal(calls.filter(u=>u.startsWith('/api/queue?')).at(-1),drill);
  await click('Patterns & indicators');
  await change('Exact host / collector','SENSOR');await change('Protocol','smb');await change('Destination port','445');await change('Pattern assessment','Changed');
  await act(async()=>{renderer.root.findAllByType('form').find(n=>n.props.className==='panel pattern-filters').props.onSubmit({preventDefault(){}});await new Promise(setImmediate)});
  assert.ok(calls.filter(u=>u.startsWith('/api/alert-groups?')).at(-1).includes('protocol=smb'));
  await click('Network destinations');
  const patternQuery=calls.filter(u=>u.startsWith('/api/network-patterns?')).at(-1);
  assert.ok(patternQuery.includes('host=SENSOR')&&patternQuery.includes('port=445')&&patternQuery.includes('review=Changed'));
  await change('Pattern network trailing window minutes','15');
  assert.equal(calls.filter(u=>u.startsWith('/api/network-patterns?')).at(-1),patternQuery);
  await act(async()=>{renderer.root.findAllByType('input').find(n=>n.props['aria-label']==='Pattern network trailing window minutes').props.onPointerUp({currentTarget:{value:'15'}});await new Promise(setImmediate)});
  const patternWindow=new URL('https://example.test'+calls.filter(u=>u.startsWith('/api/network-patterns?')).at(-1));
  assert.equal(new Date(patternWindow.searchParams.get('end'))-new Date(patternWindow.searchParams.get('start')),900000);
  assert.equal(renderer.root.findAllByType('select').find(n=>n.props['aria-label']==='Pattern time window').props.value,'custom');
  assert.equal(renderer.root.findAllByType('input').find(n=>n.props['aria-label']==='Pattern start').props.value,patternWindow.searchParams.get('start').slice(0,16));
  await click('Alert inbox');await click('Recurring patterns');
  const summaries=renderer.root.findAllByType('details').filter(n=>n.props.className==='detection-summary');assert.equal(summaries.length,1);assert.ok(text(summaries[0]).includes('4,910'));
  await act(async()=>{summaries[0].props.onToggle({currentTarget:{open:true}});await new Promise(setImmediate)});
  await click('Dismiss as safe');
  const policyForm=renderer.root.findAllByType('form').find(n=>n.props.className==='policy-editor safe');assert.ok(policyForm);
  assert.ok(text(policyForm).includes('A whole rule cannot be marked Safe'));
 }finally{
  if(renderer)await act(async()=>renderer.unmount());
 }
});

test('network pattern time controls retain results, apply on release, and preserve the displayed range and filters on drill-through',async()=>{
 globalThis.IS_REACT_ACT_ENVIRONMENT=true;
 const initial={start:'2026-10-22T06:00:00.000Z',end:'2026-10-23T06:00:00.000Z',host:'EXAMPLE-SENSOR',protocol:'smb',port:'445',source_ip:'192.0.2.20',include_safe:false};
 const queries=[],navigations=[];let hold=false,release,renderer;
 const fixture=records=>({patterns:[{key:'192.0.2.10',criteria:{destination_ip:'192.0.2.10'},destination:{ip:'192.0.2.10',label:'Example destination',address_label:'Documentation range'},records,flow_estimate:records,source_estimate:1,sources:[{ip:'192.0.2.20',label:'Example source',records}],bytes_to_server:100,bytes_to_client:50,records_with_bytes:records,ports:[{key:'445'}],protocols:[{key:'smb'}],collectors:[],server_names:[],signatures:[],sample_ref:event.ref}],talkers:[],total_flow_records:records});
 const api=async path=>{queries.push(new URL('https://example.test/api/'+path));if(hold)return new Promise(resolve=>{release=()=>resolve(fixture(7))});return fixture(3)};
 function Controlled(){const [filters,setFilters]=React.useState(initial);return React.createElement(NetworkPatterns,{api,filters,onTimeChange:next=>setFilters(f=>({...f,...next})),user:{role:'viewer'},refreshKey:0,open(){},navigate:(view,filters)=>navigations.push({view,filters})})}
 const input=label=>renderer.root.findAllByType('input').find(n=>n.props['aria-label']===label);
 const clickRecord=label=>renderer.root.findAllByType('button').find(n=>text(n)===label).props.onClick();
 try{
  await act(async()=>{renderer=create(React.createElement(Controlled),{createNodeMock:element=>element.props.className==='network-results'?{getBoundingClientRect:()=>({height:500})}:null});await new Promise(setImmediate)});
  assert.equal(new Date(queries[0].searchParams.get('end'))-new Date(queries[0].searchParams.get('start')),86400000);
  assert.ok(renderer.root.findAllByType('p').some(n=>text(n).includes('Results: 24-hour window')));
  const before=queries.length;
  await act(async()=>input('Pattern network trailing window minutes').props.onChange({target:{value:'60'}}));
  assert.equal(queries.length,before,'dragging must not fetch');
  hold=true;
  await act(async()=>{input('Pattern network trailing window minutes').props.onPointerUp({currentTarget:{value:'60'}});await new Promise(setImmediate)});
  assert.equal(queries.length,before+1);
  assert.equal(renderer.root.findAllByType('div').find(n=>n.props.className==='network-results').props.style.minHeight,500);
  assert.equal(new Date(queries.at(-1).searchParams.get('end'))-new Date(queries.at(-1).searchParams.get('start')),3600000);
  assert.ok(renderer.root.findAllByType('button').some(n=>text(n)==='3 records'),'existing rows must stay mounted while loading');
  await act(async()=>clickRecord('3 records'));
  assert.equal(navigations.at(-1).filters.start,initial.start,'pending range must not be used for old results');
  assert.equal(navigations.at(-1).filters.end,initial.end);
  await act(async()=>{release();await new Promise(setImmediate)});hold=false;
  assert.equal(renderer.root.findAllByType('div').find(n=>n.props.className==='network-results').props.style.minHeight,500);
  await act(async()=>renderer.root.findAllByType('div').find(n=>n.props.className==='network-window').props.onPointerLeave({buttons:0}));
  assert.equal(renderer.root.findAllByType('div').find(n=>n.props.className==='network-results').props.style.minHeight,260);
  await act(async()=>clickRecord('7 records'));
  const filtered=navigations.at(-1).filters;
  assert.equal(new Date(filtered.end)-new Date(filtered.start),3600000);
  for(const key of ['host','protocol','port','source_ip','include_safe'])assert.equal(filtered[key],initial[key],key);
  assert.equal(filtered.destination_ip,'192.0.2.10');assert.equal(filtered.record_type,'flow');
  await act(async()=>{input('Pattern network range start').props.onChange({target:{value:'2026-10-22T03:00'}});input('Pattern network range end').props.onChange({target:{value:'2026-10-22T03:30'}})});
  const beforeCustom=queries.length;
  await act(async()=>{renderer.root.findByType('form').props.onSubmit({preventDefault(){}});await new Promise(setImmediate)});
  assert.equal(queries.length,beforeCustom+1);assert.equal(queries.at(-1).searchParams.get('start'),'2026-10-22T03:00:00.000Z');assert.equal(queries.at(-1).searchParams.get('end'),'2026-10-22T03:30:00.000Z');
  await act(async()=>input('Pattern network range end').props.onChange({target:{value:'2026-10-22T02:30'}}));
  const beforeInvalid=queries.length;
  await act(async()=>renderer.root.findByType('form').props.onSubmit({preventDefault(){}}));
  assert.equal(queries.length,beforeInvalid);assert.ok(renderer.root.findAllByType('p').some(n=>n.props.role==='alert'));
 }finally{if(renderer)await act(async()=>renderer.unmount())}
});

test.after(async()=>{await fs.rm(folder,{recursive:true,force:true})});
