<?php
/** Global Cyber Threat Map: page view model from the stored snapshot (pure PHP; freshness is computed per request). */
defined('ABSPATH') || exit;

final class CDTM_View {
	public const PERIOD_LABELS = ['24h' => '24 h', '7d' => '7 days', '30d' => '30 days'];
	public const DEFAULT_PERIOD = '7d';
	/** Fewer countries with data than this in the shown period → "Low activity in the source right now". */
	public const LOW_ACTIVITY_COUNTRIES = 5;
	public const LOW_ACTIVITY_TEXT = 'Low activity in the source right now: fewer than 5 countries have data in this period.';
	/** When layers tie (or none is ok), this layer opens first. */
	public const PREFERRED = 'ransomware';

	public static function ago(int $seconds): string {
		$m = intdiv(max(0, $seconds), 60);
		if ($m < 1) return 'less than a minute ago';
		if ($m < 60) return $m . ' min ago';
		$h = intdiv($m, 60);
		if ($h < 48) return $h . ' h ' . ($m % 60) . ' min ago';
		return intdiv($h, 24) . ' days ago';
	}

	public static function date(?int $t): string { return is_int($t) ? gmdate('Y-m-d H:i', $t) . ' UTC' : ''; }

	/** A value as the page writes it: counts as integers, shares as the source's percentage with two decimals. */
	public static function value_text(string $kind, $n): string {
		return $kind === 'share' ? number_format((float) $n, 2) . '%' : number_format_i18n((int) $n);
	}

	/**
	 * Tab order and default tab from the data: layers in status ok first, by the number of countries with data in
	 * the default period (most first); ties keep the definition order (Ransomware.live first). The rest follow in
	 * definition order. If no layer is ok, Ransomware.live opens first with its own status.
	 */
	public static function order(array $layers): array {
		$rank = array_flip(array_keys(CDTM::layers()));
		usort($layers, static function ($a, $b) use ($rank) {
			$ok = [$a['status'] === 'ok' ? 0 : 1, $b['status'] === 'ok' ? 0 : 1];
			if ($ok[0] !== $ok[1]) return $ok[0] <=> $ok[1];
			if ($ok[0] === 0 && $a['countries'] !== $b['countries']) return $b['countries'] <=> $a['countries'];
			return $rank[$a['id']] <=> $rank[$b['id']];
		});
		if ($layers[0]['status'] !== 'ok') {
			$i = array_search(self::PREFERRED, array_column($layers, 'id'), true);
			if ($i !== false && $i !== 0) array_unshift($layers, array_splice($layers, $i, 1)[0]);
		}
		return $layers;
	}

	/** @return array{now:int, layers:list<array>, names:array, empty:bool, default:string} */
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
				$with = array_filter($data['countries'] ?? [], static fn($row) => $row['n'] > 0);
				$top = [];
				foreach (array_slice($with, 0, 10, true) as $cc => $row) {
					$top[] = ['cc' => $cc, 'name' => $names[$cc] ?? $cc, 'n' => $row['n'], 'text' => self::value_text($def['kind'], $row['n'])];
				}
				$since = $s['history_since'] ?? null;
				$periods[$p] = [
					'label' => $label,
					'top' => $top,
					'countries' => count($with),
					'low' => $data !== null && count($with) < self::LOW_ACTIVITY_COUNTRIES,
					'complete' => (bool) ($data['complete'] ?? false),
					'comparable' => (bool) ($data['comparable'] ?? false),
					'collecting' => $data && empty($data['comparable']) && is_int($since) ? 'Collecting data since ' . gmdate('Y-m-d', $since) . '; no comparison with the previous period yet.' : '',
					'unknown' => $data['unknown'] ?? 0,
				];
			}
			$layers[] = $def + [
				'status' => $status, 'status_text' => $text, 'show' => $show, 'last_success' => $last,
				'error_retrying' => $show && !empty($s['last_error_at']),
				'countries' => $periods[self::DEFAULT_PERIOD]['countries'],
				'periods' => $periods,
			];
		}
		$layers = self::order($layers);
		return ['now' => $now, 'layers' => $layers, 'names' => $names, 'empty' => $snapshot === null, 'default' => $layers[0]['id']];
	}

	/** ISO codes that have a flag file in the theme (assets/flags/flags.json). */
	public static function flag_codes(): array {
		static $codes = null;
		if ($codes === null) {
			$file = dirname(__DIR__, 2) . '/assets/flags/flags.json';
			$data = is_file($file) ? json_decode((string) file_get_contents($file), true) : null;
			$codes = array_keys($data['files'] ?? []);
		}
		return $codes;
	}

	/** Data for the script: only what the page shows (counts or shares, labels and timestamps). */
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
		return ['schema' => 1, 'now' => $model['now'], 'period' => self::DEFAULT_PERIOD, 'labels' => self::PERIOD_LABELS, 'names' => $model['names'],
			'layers' => $layers, 'flags' => implode(',', self::flag_codes()), 'low' => self::LOW_ACTIVITY_COUNTRIES];
	}
}
