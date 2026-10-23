import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {eligibleForClear,clearItems,toggleSelection} from './queue-actions.mjs';
const alert={ref:{index:'wazuh-alerts-4.x-test',id:'one'},state:{status:'Investigating',updated:123}};
test('selection retains the expected state for conflict detection',()=>{
 const selected=toggleSelection({},alert);assert.deepEqual(clearItems(Object.values(selected)),[{index:alert.ref.index,eid:'one',expected_status:'Investigating',expected_updated:123}]);
 assert.deepEqual(toggleSelection(selected,alert),{});assert.equal(Object.keys(selected).length,1);
});
test('raw archives and closed alerts cannot be selected',()=>{
 for(const e of [{...alert,ref:{...alert.ref,index:'wazuh-archives-test'}},{...alert,state:{status:'Closed'}}]){
  assert.equal(eligibleForClear(e),false);assert.deepEqual(toggleSelection({},e),{});
 }
});
test('theme preference overrides OS and blocked storage falls back safely',()=>{
 const script=fs.readFileSync(new URL('../public/theme.js',import.meta.url),'utf8');
 for(const [saved,os,expected,blocked] of [['light',true,'light'],['dark',false,'dark'],['invalid',true,'dark'],[null,false,'light'],[null,true,'dark',true]]){
  const document={documentElement:{dataset:{}}};vm.runInNewContext(script,{document,window:{matchMedia:()=>({matches:os})},localStorage:{getItem:()=>{if(blocked)throw Error('blocked');return saved;}}});
  assert.equal(document.documentElement.dataset.theme,expected);
 }
});
