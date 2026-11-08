<?php
/** Small server-rendered charts; data is already aggregated by Research Agent. */
defined('ABSPATH') || exit;
function cyberdat_chart_number($v){return rtrim(rtrim(number_format((float)$v,4,'.',''),'0'),'.')?:'0';}
function cyberdat_chart_table($values,$heading){
 echo '<details class="td-chart-data"><summary>'.esc_html($heading).'</summary><div class="td-scroll" tabindex="0" role="region" aria-label="'.esc_attr($heading).'"><table><thead><tr><th>UTC date / category</th><th>Records</th></tr></thead><tbody>';
 foreach($values as $label=>$value){echo '<tr><th>'.esc_html($label).'</th><td>'.esc_html(number_format_i18n($value)).'</td></tr>';}
 echo '</tbody></table></div></details>';
}
function cyberdat_chart_line($id,$values,$periods,$caption){
 $selected=30;$window=array_slice($values,-$selected,null,true);$max=max(1,...array_values($window));$points=[];$i=0;$denom=max(1,count($window)-1);
 foreach($window as $date=>$count){$points[]=['x'=>44+512*$i/$denom,'y'=>174-140*$count/$max,'date'=>$date,'count'=>$count];$i++;}
 echo '<div class="td-chart" data-chart-line="'.esc_attr($id).'" data-series="'.esc_attr(wp_json_encode($values)).'"><div class="td-chart-controls" role="group" aria-label="'.esc_attr($caption.' period').'" hidden>';
 foreach($periods as $days){echo '<button type="button" data-period="'.esc_attr($days).'" aria-pressed="'.($days===$selected?'true':'false').'">'.esc_html($days.' days').'</button>';}
 echo '</div><p class="td-chart-window" data-chart-window>'.esc_html(array_key_first($window).' → '.array_key_last($window).' · '.array_sum($window).' records').'</p>';
 echo '<svg class="td-line-svg" viewBox="0 0 600 215" preserveAspectRatio="none" role="group" aria-labelledby="'.esc_attr($id.'-title').' '.esc_attr($id.'-desc').'"><title id="'.esc_attr($id.'-title').'">'.esc_html($caption).'</title><desc id="'.esc_attr($id.'-desc').'" data-chart-description>'.esc_html(implode('; ',array_map(static fn($d,$v)=>$d.': '.$v,array_keys($window),array_values($window)))).'</desc><path d="M44 34H556M44 104H556M44 174H556" stroke="#293e4d" fill="none"/><g class="td-svg-axis" fill="#b5c9d8" font-size="12"><text x="6" y="38" data-chart-max>'.esc_html($max).'</text><text x="18" y="178">0</text><text x="44" y="199" data-chart-first>'.esc_html(array_key_first($window)).'</text><text x="458" y="199" data-chart-last>'.esc_html(array_key_last($window)).'</text></g><g data-chart-plot><polyline points="';
 echo esc_attr(implode(' ',array_map(static fn($p)=>cyberdat_chart_number($p['x']).','.cyberdat_chart_number($p['y']),$points)));
 echo '" class="td-chart-path" fill="none" stroke="#70f3cb" stroke-width="2.5"/>';
 foreach($points as $point){$label=$point['date'].' UTC · '.$point['count'].' records';echo '<circle cx="'.esc_attr(cyberdat_chart_number($point['x'])).'" cy="'.esc_attr(cyberdat_chart_number($point['y'])).'" r="7" class="td-chart-point" tabindex="0" data-tooltip="'.esc_attr($label).'" aria-label="'.esc_attr($label).'"><title>'.esc_html($label).'</title></circle>';}
 echo '</g></svg><p class="td-axis-label">X: UTC calendar date · Y: records per day</p><p class="td-chart-tooltip" role="status" aria-live="polite" data-chart-tooltip>Focus, tap or hover a point to inspect its value.</p>';
 cyberdat_chart_table($values,__('Full 90-day data · available without JavaScript','cyberdat'));echo '</div>';
}
function cyberdat_chart_ring($id,$values,$colors,$center,$description){
 $total=array_sum($values);$offset=0;echo '<div class="td-ring-layout"><svg class="td-ring" viewBox="0 0 220 220" role="group" aria-labelledby="'.esc_attr($id.'-title').' '.esc_attr($id.'-desc').'"><title id="'.esc_attr($id.'-title').'">'.esc_html($description).'</title><desc id="'.esc_attr($id.'-desc').'">'.esc_html(implode('; ',array_map(static fn($k,$v)=>$k.': '.$v,array_keys($values),array_values($values)))).'</desc><circle cx="110" cy="110" r="80" fill="none" stroke="#243340" stroke-width="22"/>';
 foreach($values as $label=>$value){$part=$total?100*$value/$total:0;$tip=$label.' · '.$value.' / '.$total.' · '.number_format($part,1).'%';if($value>0){echo '<circle class="td-ring-segment" cx="110" cy="110" r="80" pathLength="100" fill="none" stroke="'.esc_attr($colors[$label]).'" stroke-width="22" stroke-dasharray="'.esc_attr(cyberdat_chart_number($part).' '.cyberdat_chart_number(100-$part)).'" stroke-dashoffset="'.esc_attr(cyberdat_chart_number(-$offset)).'" transform="rotate(-90 110 110)" tabindex="0" data-tooltip="'.esc_attr($tip).'" aria-label="'.esc_attr($tip).'"><title>'.esc_html($tip).'</title></circle>';}$offset+=$part;}
 echo '<text x="110" y="110" text-anchor="middle" fill="#edf6fa" font-size="28" font-weight="650">'.esc_html(number_format_i18n($total)).'</text><text x="110" y="132" text-anchor="middle" fill="#a6b5c4" font-size="10">'.esc_html($center).'</text></svg><ul class="td-chart-legend">';
 foreach($values as $label=>$value){echo '<li><span class="td-legend-dot" style="background:'.esc_attr($colors[$label]).'"></span><span>'.esc_html($label).'</span><strong>'.esc_html(number_format_i18n($value)).'</strong><small>'.esc_html($total?number_format(100*$value/$total,1).'%':'Not Available').'</small></li>';}
 echo '</ul></div><p class="td-chart-tooltip" role="status" aria-live="polite" data-chart-tooltip>Focus, tap or hover a segment to inspect its share.</p>';
}
