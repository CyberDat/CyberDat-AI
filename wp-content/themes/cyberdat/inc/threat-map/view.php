<?php
/** Global Cyber Threat Map: page view model from the stored snapshot (pure PHP; freshness is computed per request). */
defined('ABSPATH') || exit;

final class CDTM_View {
	public const PERIOD_LABELS = ['24h' => '24 h', '7d' => '7 days', '30d' => '30 days'];
	public const DEFAULT_PERIOD = '7d';

	public static function ago(int $seconds): string {
		$m = intdiv(max(0, $seconds), 60);
		if ($m < 1) return 'less than a minute ago';
		if ($m < 60) return $m . ' min ago';
		$h = intdiv($m, 60);
		if ($h < 48) return $h . ' h ' . ($m % 60) . ' min ago';
		return intdiv($h, 24) . ' days ago';
	}

	public static function date(?int $t): string { return is_int($t) ? gmdate('Y-m-d H:i', $t) . ' UTC' : ''; }

	/** @return array{now:int, layers:list<array>, names:array, empty:bool} */
	public static function model(?array $snapshot, int $now): array {
		$names = $snapshot['names'] ?? [];
		$layers = [];
		foreach (CDTM::layers() as $id => $def) {
			$s = $snapshot['layers'][$id] ?? null;
			$configured = $s ? (bool) $s['configured'] : CDTM::configured($def);
			$state = ['last_success' => $s['last_success'] ?? null];
			$status = CDTM::freshness($state, $now, $configured);
			$last = $state['last_success'];
			if ($status === 'not_configured') {
				$text = 'Not configured: this layer needs a source API key on the CyberDat server. No data is shown.';
			} elseif (!is_int($last)) {
				$text = 'Data unavailable: waiting for the first successful collection.';
			} elseif ($status === 'unavailable') {
				$text = 'Data unavailable since ' . self::date($last) . '. Older numbers are not shown as current.';
			} elseif ($status === 'stale') {
				$text = 'Stale: last successful update ' . self::ago($now - $last) . ' (' . self::date($last) . '). Collection is retrying.';
			} else {
				$text = 'Updated ' . self::ago($now - $last) . ' (' . self::date($last) . ').';
			}
			$show = in_array($status, ['ok', 'stale'], true);
			$periods = [];
			foreach (self::PERIOD_LABELS as $p => $label) {
				$data = $show ? ($s['periods'][$p] ?? null) : null;
				$top = [];
				foreach (array_slice($data['countries'] ?? [], 0, 10, true) as $cc => $row) {
					if ($row['n'] > 0) $top[] = ['cc' => $cc, 'name' => $names[$cc] ?? $cc, 'n' => $row['n']];
				}
				$since = $s['history_since'] ?? null;
				$periods[$p] = [
					'label' => $label,
					'top' => $top,
					'complete' => (bool) ($data['complete'] ?? false),
					'comparable' => (bool) ($data['comparable'] ?? false),
					'collecting' => $data && empty($data['comparable']) && is_int($since) ? 'Collecting data since ' . gmdate('Y-m-d', $since) . '; no comparison with the previous period yet.' : '',
					'unknown' => (int) ($data['unknown'] ?? 0),
				];
			}
			$layers[] = $def + [
				'status' => $status, 'status_text' => $text, 'show' => $show, 'last_success' => $last,
				'error_retrying' => $show && !empty($s['last_error_at']),
				'periods' => $periods,
			];
		}
		return ['now' => $now, 'layers' => $layers, 'names' => $names, 'empty' => $snapshot === null];
	}

	/** Data for the script: only what the page shows (counts, labels and timestamps). */
	public static function client_data(?array $snapshot, array $model): array {
		$layers = [];
		foreach ($model['layers'] as $l) {
			$s = $snapshot['layers'][$l['id']] ?? [];
			$periods = [];
			if ($l['show']) foreach (array_keys(self::PERIOD_LABELS) as $p) $periods[$p] = $s['periods'][$p] ?? null;
			$layers[$l['id']] = [
				'id' => $l['id'], 'name' => $l['name'], 'source' => $l['source'], 'short' => $l['short'], 'unit' => $l['unit'],
				'breakdown' => $l['breakdown'], 'kind' => $l['kind'], 'status' => $l['status'], 'last_success' => $l['last_success'],
				'history_since' => $s['history_since'] ?? null, 'records_url' => $l['records_url'], 'records_label' => $l['records_label'],
				'periods' => $periods,
			];
		}
		return ['schema' => 1, 'now' => $model['now'], 'period' => self::DEFAULT_PERIOD, 'labels' => self::PERIOD_LABELS, 'names' => $model['names'], 'layers' => $layers];
	}
}
