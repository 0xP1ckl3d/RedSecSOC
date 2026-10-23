export const eligibleForClear = event => event.ref.index.startsWith('wazuh-alerts-') && event.state?.status !== 'Closed';

export function clearItems(events) {
  return events.map(event => ({index:event.ref.index,eid:event.ref.id,expected_status:event.state?.status||'New',expected_updated:event.state?.updated??null}));
}

export function toggleSelection(selection,event) {
  const next={...selection},key=event.ref.index+'|'+event.ref.id;
  if(next[key])delete next[key];else if(eligibleForClear(event))next[key]=event;
  return next;
}
