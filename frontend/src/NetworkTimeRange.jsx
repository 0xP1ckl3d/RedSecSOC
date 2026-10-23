import React,{useEffect,useId,useLayoutEffect,useRef,useState} from 'react';

const utcInput=value=>new Date(value).toISOString().slice(0,16);
const durationOf=value=>Math.max(15,Math.min(2880,Math.round((new Date(value.end)-new Date(value.start))/900000)*15));
export const rangeDescription=value=>{
 const minutes=(new Date(value.end)-new Date(value.start))/60000;
 const length=minutes<60?`${Number(minutes.toFixed(2)).toLocaleString()}-minute`:`${Number((minutes/60).toFixed(2)).toLocaleString()}-hour`;
 return `${length} window · ${new Date(value.start).toLocaleString()} — ${new Date(value.end).toLocaleString()}`;
};

// Keep the result region from shrinking during a range change in either view.
export function useStableRegion(data){
 const region=useRef(null),locked=useRef(false),[floor,setFloor]=useState(260);
 const freeze=()=>{locked.current=true;const height=region.current?.getBoundingClientRect?.().height;if(height)setFloor(h=>Math.max(h,height))};
 const release=()=>{locked.current=false;setFloor(260)};
 useLayoutEffect(()=>{if(locked.current)freeze();else setFloor(260)},[data]);
 return {region,floor,freeze,release};
}

export default function NetworkTimeRange({value,onApply,beforeApply=()=>{},afterInteraction=()=>{},label='Network'}){
 const id=useId(),[duration,setDuration]=useState(()=>durationOf(value)),[draft,setDraft]=useState(()=>({start:utcInput(value.start),end:utcInput(value.end)})),[error,setError]=useState('');
 const appliedDuration=useRef(duration);
 useEffect(()=>{const minutes=durationOf(value);setDuration(minutes);appliedDuration.current=minutes;setDraft({start:utcInput(value.start),end:utcInput(value.end)})},[value.start,value.end]);
 function apply(next){
  const span=new Date(next.end)-new Date(next.start);
  if(!Number.isFinite(span)||span<=0||span>31*86400000){setError('Select an increasing time range of at most 31 days.');return}
  setError('');beforeApply();onApply(next);
 }
 function rolling(minutes){const now=new Date();appliedDuration.current=minutes;setDuration(minutes);apply({start:new Date(now-minutes*60000).toISOString(),end:now.toISOString()})}
 return <><div className="network-window" onPointerLeave={e=>{if(!e.buttons)afterInteraction()}} onBlur={e=>{if(!e.currentTarget.contains(e.relatedTarget))afterInteraction()}} role="group" aria-label={label+' time controls'}><div className="range-control"><label htmlFor={id}>Trailing window (release to apply): {duration<60?duration+' minutes':(duration/60).toLocaleString()+' hours'}</label><input id={id} aria-label={label+' trailing window minutes'} type="range" min="15" max="2880" step="15" value={duration} onPointerDown={e=>{beforeApply();e.currentTarget.setPointerCapture?.(e.pointerId)}} onChange={e=>setDuration(Number(e.target.value))} onPointerUp={e=>rolling(Number(e.currentTarget.value))} onKeyUp={e=>{if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown','PageUp','PageDown','Home','End'].includes(e.key))rolling(Number(e.currentTarget.value))}} onBlur={()=>{if(duration!==appliedDuration.current)rolling(duration)}}/><button onClick={()=>rolling(1440)}>Last 24 hours</button><button onClick={()=>rolling(duration)}>Refresh trailing window</button></div><form className="exact-window" onSubmit={e=>{e.preventDefault();apply({start:new Date(draft.start+'Z').toISOString(),end:new Date(draft.end+'Z').toISOString()})}}><label>From (UTC)<input aria-label={label+' range start'} type="datetime-local" required value={draft.start} onChange={e=>setDraft(d=>({...d,start:e.target.value}))}/></label><label>To (UTC)<input aria-label={label+' range end'} type="datetime-local" required value={draft.end} onChange={e=>setDraft(d=>({...d,end:e.target.value}))}/></label><button>Apply time range</button></form></div>{error&&<p className="error" role="alert">{error}</p>}<p className="window-caption">Selected {rangeDescription(value)} · Times shown in your browser timezone; exact inputs use UTC.</p></>;
}
