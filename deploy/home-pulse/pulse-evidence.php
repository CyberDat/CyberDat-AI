<?php
/** Read existing projection only; no queries beyond the existing data provider. */
cdra_need(cdra_staging(),'staging_only');$d=cyberdat_research_dashboard();cdra_need(is_array($d),'missing_projection');
$periods=[];foreach(['kev','nvd'] as $source){foreach([7,30,90] as $days){$periods[$source][$days]=cyberdat_pulse_period($d['chart_series'][$source]??[],$days);}}
$signal=cyberdat_pulse_signal($d['feed'],(int)$d['generated_at']);
echo wp_json_encode(['generated_at'=>$d['generated_at'],'counts'=>$d['counts'],'severity'=>$d['severity'],'versions'=>$d['versions'],'periods'=>$periods,'series'=>$d['chart_series'],'signal'=>$signal?array_intersect_key($signal,array_flip(['id','url','published','severity','source','kev'])):null,'sync'=>['kev'=>cyberdat_pulse_sync($d,'kev'),'nvd'=>cyberdat_pulse_sync($d,'nvd')]]);
