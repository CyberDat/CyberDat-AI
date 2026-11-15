/*
 * Generated inputs for the AI Model BOM tests (synthetic; example.* hosts; digests derived from counters).
 * bigBom(bytes): a CycloneDX 1.7 document of about <bytes> characters with one model and many datasets,
 * weights files and libraries, mixing English, German, Russian and NFD names.
 */
'use strict';
const crypto = require('node:crypto');

function bigBom(bytes) {
	const comps = [{ type: 'machine-learning-model', 'bom-ref': 'model-1', name: 'Größes Modell', version: '4.0.1', supplier: { name: 'Beispiel GmbH' }, licenses: [{ license: { id: 'Apache-2.0' } }], properties: [{ name: 'cyberdat:aibom:model-type', value: 'own' }], modelCard: { considerations: { useCases: ['Stress test'], technicalLimitations: ['Synthetic'] }, quantitativeAnalysis: { performanceMetrics: [{ type: 'accuracy', value: '0.9' }] } } }];
	const names = ['Обращения', 'Größenklassen', 'Invoices', 'Пётр', 'Jörg'];
	let size = 600, datasets = 0, i = 0;
	while (size < bytes) {
		const k = i++ % 3;
		let c;
		if (k === 0) { datasets++; c = { type: 'data', 'bom-ref': 'data-' + i, name: names[i % names.length] + ' ' + i, licenses: [{ license: { id: 'CC-BY-4.0' } }], data: [{ type: 'dataset', contents: { url: 'https://data.example.com/sets/' + i } }], properties: [{ name: 'cyberdat:aibom:personal-data', value: i % 7 ? 'no' : 'unknown' }] }; }
		else if (k === 1) { c = { type: 'file', 'bom-ref': 'weights-' + i, name: 'shard-' + i + (i % 11 ? '.safetensors' : '.bin'), hashes: [{ alg: 'SHA-256', content: crypto.createHash('sha256').update(String(i)).digest('hex') }], externalReferences: [{ type: 'distribution', url: 'https://models.example.com/shards/' + i }] }; }
		else { c = { type: 'library', 'bom-ref': 'lib-' + i, name: 'lib-' + i, version: i % 13 ? '1.' + (i % 50) + '.0' : '' }; }
		comps.push(c);
		size += JSON.stringify(c, null, 2).length + 4;
	}
	const bom = { bomFormat: 'CycloneDX', specVersion: '1.7', serialNumber: 'urn:uuid:5f1d8a9e-1c2b-4a3d-8e7f-0a1b2c3d4e5f', version: 1, metadata: { supplier: { name: 'Beispiel GmbH', contact: [{ name: 'Ömer', email: 'oemer@example.de' }] } }, components: comps };
	let text = JSON.stringify(bom, null, 2);
	while (text.length > bytes) {
		const drop = Math.max(1, Math.ceil((text.length - bytes) / 400));
		for (const c of comps.splice(comps.length - drop, drop)) { if (c.type === 'data') { datasets--; } }
		text = JSON.stringify(bom, null, 2);
	}
	return { text, components: comps.length, datasets };
}

module.exports = { bigBom };
