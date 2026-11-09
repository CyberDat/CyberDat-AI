const assert=require('node:assert/strict');
const {selectionLabel}=require('../wp-content/themes/cyberdat/assets/js/threat-analytics.js');
for(const [group,values] of Object.entries({severity:['Critical','High','Medium','Low','None','Unrated'],overlap:['shared','kev_only','nvd_only'],ransomware:['known','not_known'],advisory:['cisa-advisories','cert-eu','msrc']})){
 for(const value of values){const label=selectionLabel(group,value);assert.notEqual(label,value);assert.notEqual(label,'Verified source records');assert(!label.includes('undefined'));}
}
assert(selectionLabel('overlap','kev_only').includes('local NVD'));
assert(selectionLabel('ransomware','not_known').includes('not marked Known'));
assert.equal(selectionLabel('invalid','invalid'),'Verified source records');
console.log('PASS: human-readable headings and accessible labels for all 14 drill filters, including gray overlap segments');
