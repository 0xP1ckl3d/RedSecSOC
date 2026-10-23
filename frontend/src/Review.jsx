import React,{useState,useEffect} from 'react';
import {ExternalLink,RefreshCw,CheckCheck} from 'lucide-react';
import {clearItems,eligibleForClear} from './queue-actions.mjs';

const stamp=v=>v?new Date(v).toLocaleString():'Not observed';
export function Interpretation({assessment}){
 if(!assessment)return null;
 return <section className="panel interpretation"><div className="section-heading"><h2>Evidence-based interpretation</h2><span className="badge blue">{assessment.posture}</span></div><p>{assessment.summary}</p>{assessment.basis.map((b,i)=><div className="interpretation-basis" key={i}><strong>{b.meaning}</strong><pre>{b.value}</pre><small>{b.field}</small></div>)}{assessment.caveats.map((c,i)=><p className="muted small" key={i}>{c}</p>)}{assessment.references.map(r=><a className="reference-link" href={r.url} target="_blank" rel="noreferrer" key={r.url}>{r.title}<ExternalLink size={12}/></a>)}</section>
}

export function EvidenceStages({sequence,open}){
 if(!sequence)return null;
 return <section className="panel"><h2>Evidence stages</h2><p>{sequence.notice}</p>{sequence.partial&&<p className="notice">The retrieved window is partial. Narrow the window to inspect missing evidence.</p>}<div className="evidence-stages">{sequence.stages.map(s=><div key={s.id}><div className="section-heading"><h3>{s.label}</h3><span className={'badge '+(s.linked_count?'blue':'')}>{s.status}</span></div><small>{s.count} observations · {s.linked_count} identifier/session/flow associations</small>{s.observations.map((e,i)=><button className="stage-event" key={i} onClick={()=>open(e.ref)}><strong>{e.host}: {e.title}</strong><span>{e.subject}</span><small>{stamp(e.time)} · {e.relation.basis}</small></button>)}{s.truncated&&<p>Only the first 30 observations are shown in this stage.</p>}</div>)}</div></section>
}

export function ObservationChecklist({data}){
 if(!data)return null;
 return <section className="panel"><h2>Telemetry observations — last 24 hours</h2><p>{data.notice}</p><div className="table-scroll"><table><thead><tr><th>Host / registration</th><th>Reporting</th><th>Event sources observed</th><th>Triggered alerts</th></tr></thead><tbody>{data.rows.map(r=><tr key={r.name}><td><strong>{r.name}</strong><small>{r.registered?'Registered':'Not registered'} · {r.platform}</small></td><td>{r.agent_status}<small>{r.raw_count.toLocaleString()} raw records</small><small>{stamp(r.latest)}</small></td><td><details><summary>{r.signals.filter(s=>s.count>0).length} of {r.signals.length} listed source types observed</summary>{r.signals.map(s=><p className="small" key={s.id}><strong>{s.label}:</strong> {s.status}{s.count?' ('+s.count.toLocaleString()+')':''}</p>)}</details></td><td>{r.alerts_in_retained_indices.toLocaleString()}<small>In retained alert indices; separate from the 24-hour source checklist</small></td></tr>)}</tbody></table></div></section>
}

export {PatternWorkbench as AlertGroups} from './Patterns.jsx';
