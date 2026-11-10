<?php
/** Reviewed real-title/excerpt regressions; no live calls or DB. */
define('ABSPATH','/offline/');function wp_json_encode($v,$f=0){return json_encode($v,$f);}function wp_parse_url($s,$c=-1){return parse_url($s,$c);}function wp_strip_all_tags($s){return strip_tags($s);}
$b=__DIR__.'/../wp-content/plugins/cyberdat-research/includes/';foreach(['registry','normalize','discovery'] as $file){require $b.$file.'.php';}
$cases=[
 ['TUTTI: Parallel CKKS Bootstrapping in under 3 ms on CPU','New methods for exploiting parallelism and increasing the number of messages.','papers',['Cryptography & Privacy'],['Vulnerabilities']],
 ['BioBind: Binding Biometric Deduplication to Zero-Knowledge Authentication','Biometric enrollment and cryptographic privacy guarantees.','papers',['Cryptography & Privacy'],['AI Security','LLM & Agent Security']],
 ['VerifiedIDA | Making LLM-Driven Reverse Engineering Inspectable, Continuable and Reusable','LLM reverse engineering requires inspectable analysis and security evidence.','research',['AI Security','LLM & Agent Security','Reverse Engineering'],[]],
 ['Suppression Is Not Erasure: LoRA Backdoor Defense','Third-party LoRA adapters for large language models can contain model backdoors.','papers',['AI Security','LLM & Agent Security'],['Malware']],
 ['How Far Does Second-Order Linear Response Predict Quantization Mismatch? Measurements on Five Language Models','GPU quantization performance measurements and rounding modes.','papers',[],['AI Security','LLM & Agent Security']],
 ['WhiteMatter Raises $20 Million in Series A Funding','A dedicated guardian agent for every AI agent in an organization.','news',['AI Security'],[]],
 ['Checking DER Commands Against Grid Context Catches Credentialed Attacks','Distributed energy resource commands are checked against grid context.','papers',['IoT / ICS / OT'],[]],
 ['Reconfiguring System-Level Protection Through Bounded Delegation in RISC-V MCUs','Embedded and cyber-physical systems require bounded protection.','papers',['IoT / ICS / OT'],[]],
 ['Turning Up the Heat: Attacks on Europe’s Refrigeration Systems','Connected refrigeration systems are attacked.','research',['IoT / ICS / OT'],[]],
 ['Windows Exploitation Techniques: Dangling COM Object Registrations','Privilege escalation CVE-2026-66804.','research',['Vulnerabilities'],[]],
 ['An unrelated enrollment study','Smallmodels and email enrollment.','papers',[],['AI Security','LLM & Agent Security']],
 ['Over a Dozen Organizations Hit in Qubole Supply Chain Attack','Compromised credentials used in a supply chain attack.','news',['Incident Response'],[]],
 ['[NEU] [mittel] 7-Zip: Mehrere Schwachstellen ermöglichen nicht spezifizierten Angriff','Official CERT-Bund advisory metadata.','research',['Vulnerabilities'],[]],
 ['Reverse-engineering malware','Decompilation of a malware sample.','research',['Reverse Engineering','Malware'],[]],
];
$n=0;foreach($cases as [$title,$summary,$stream,$yes,$no]){$c=cdra_discovery_classify($title,$summary,$stream);foreach($yes as $cat){if(!in_array($cat,$c['categories'],true)){throw new RuntimeException('Missing '.$cat.': '.$title);}}foreach($no as $cat){if(in_array($cat,$c['categories'],true)){throw new RuntimeException('False '.$cat.': '.$title);}}++$n;}
$feed='<rss xmlns:dc="http://purl.org/dc/elements/1.1/"><channel><item><guid>fixture</guid><title>TEST Security</title><link>https://techcommunity.microsoft.com/blog/security/test</link><pubDate>2020-01-01T00:00:00Z</pubDate><dc:creator>TEST Author</dc:creator><description>TEST</description></item></channel></rss>';
$r=cdra_discovery_parse('ms-security',$feed)[0];if($r['authors']!==['TEST Author']){throw new RuntimeException('RSS creator lost');}
$bad=str_replace('techcommunity.microsoft.com','techcommunity.microsoft.com.evil.example',$feed);try{cdra_discovery_parse('ms-security',$bad);throw new RuntimeException('Lookalike host accepted');}catch(CDRA_Error $e){if($e->getMessage()!=='unapproved_source_link'){throw $e;}}
$url=cdra_discovery_url('https://sec.cloudapps.cisco.com/advisory?vs_f=tracking&id=123',['vs_f']);if($url!=='https://sec.cloudapps.cisco.com/advisory?id=123'){throw new RuntimeException('Cisco tracking normalization');}
$record=cdra_discovery_record('cisco-advisories','fixture','https://sec.cloudapps.cisco.com/advisory?vs_f=tracking&id=123','TEST','TEST','2020-01-01T00:00:00Z');if($record['original_url']===$record['canonical_url']){throw new RuntimeException('Original source URL lost');}
$timezone=date_default_timezone_get();date_default_timezone_set('Europe/Berlin');if(cdra_discovery_timestamp('2020-01-01 12:00:00.0')!=='2020-01-01T12:00:00Z'||cdra_discovery_timestamp('Nov 05, 2020 00:00:00-0600')!=='2020-11-05T06:00:00Z'){throw new RuntimeException('Source timezone context');}date_default_timezone_set($timezone);
echo "PASS: $n classification regressions (reviewed titles/excerpts and negative controls), explicit publisher host allowlist, RSS author and source-specific canonical tracking; no LLM/DB/network\n";
