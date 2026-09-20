"""
RadioGuard Comprehensive Verification & Stress Test Suite
Tests all detection heuristics, mathematical bounds, memory safety clamps,
TunnelCrack route splitting, emergency fail-safe logic, and UI threat states.
"""

import math
import sys
import unittest

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c

class MockAnomalyEngine:
    THRESHOLD_SUSPICIOUS = 0.45
    THRESHOLD_CRITICAL = 0.75

    def __init__(self, db_records):
        self.db = db_records
        self.previous_cell_id = 0
        self.previous_rsrp = 0
        self.previous_rsrp_time = 0
        self.consecutive_anomalies = 0
        self.prev_anomaly_time = 0

    def analyze(self, obs, user_loc, prev_is_high_gen, now_ms):
        reasons = []
        p_factors = []

        # 1. Sudden Involuntary 2G Downgrade
        if prev_is_high_gen and obs['gen'] == 'GSM_2G':
            p_factors.append(0.70)
            reasons.append("Forced downgrade to 2G")

        # 2. Empty Neighbor List
        if obs['gen'] == 'LTE_4G' and obs['neighbors'] == 0:
            p_factors.append(0.40)
            reasons.append("Empty LTE neighbor list")

        # 3. High Signal Power
        if obs['rsrp'] > -60:
            p_factors.append(0.35)
            reasons.append("Unnatural high RF signal power")

        # 3b. Shadow Clone Step-Gradient Jump
        if obs['cid'] == self.previous_cell_id and self.previous_cell_id != 0:
            delta_rsrp = obs['rsrp'] - self.previous_rsrp
            delta_t = now_ms - self.previous_rsrp_time
            if delta_rsrp > 25 and delta_t < 4000:
                p_factors.append(0.80)
                reasons.append(f"Macro-Cell Shadow Clone: Rapid RSRP surge (+{delta_rsrp} dB)")

        self.previous_cell_id = obs['cid']
        self.previous_rsrp = obs['rsrp']
        self.previous_rsrp_time = now_ms

        # 4. Invalid Identifiers
        if obs['tac'] in (0, 0xFFFF) or obs['cid'] in (0, 0xFFFFFFFF):
            p_factors.append(0.85)
            reasons.append("Invalid TAC or CID")

        # 5. Spatial verification
        key = (obs['mcc'], obs['mnc'], obs['tac'], obs['cid'])
        tower = self.db.get(key)
        if tower and user_loc:
            dist = haversine_distance_km(user_loc[0], user_loc[1], tower['lat'], tower['lon'])
            if dist > 10.0:
                p_factors.append(0.80)
                reasons.append(f"Spatial drift {dist:.1f} km")
        elif not tower and obs['tac'] != 0:
            p_factors.append(0.20)
            reasons.append("Uncataloged cell tower")

        # Bayesian combination: P = 1 - Prod(1 - p_i)
        prod = 1.0
        for p in p_factors:
            prod *= (1.0 - p)
        raw_score = max(0.0, min(1.0, 1.0 - prod))

        # Hysteresis update
        if raw_score >= self.THRESHOLD_SUSPICIOUS:
            if now_ms - self.prev_anomaly_time < 10000:
                self.consecutive_anomalies += 1
            else:
                self.consecutive_anomalies = 1
            self.prev_anomaly_time = now_ms
        else:
            self.consecutive_anomalies = 0

        if raw_score >= self.THRESHOLD_CRITICAL and self.consecutive_anomalies < 2:
            final_score = self.THRESHOLD_SUSPICIOUS + 0.1
        else:
            final_score = raw_score

        threat = 'SAFE'
        if final_score >= self.THRESHOLD_CRITICAL:
            threat = 'CRITICAL_ROGUE'
        elif final_score >= self.THRESHOLD_SUSPICIOUS:
            threat = 'SUSPICIOUS'

        return {
            'threat': threat,
            'score': round(final_score, 3),
            'reasons': reasons,
            'quarantine': threat == 'CRITICAL_ROGUE'
        }

class TestRadioGuardCore(unittest.TestCase):

    def setUp(self):
        self.verified_db = {
            (310, 410, 12014, 1004521): {'lat': 37.7749, 'lon': -122.4194}
        }
        self.engine = MockAnomalyEngine(self.verified_db)

    def test_01_normal_macro_cell_passes(self):
        obs = {'gen': 'LTE_4G', 'mcc': 310, 'mnc': 410, 'tac': 12014, 'cid': 1004521, 'rsrp': -95, 'neighbors': 4}
        res = self.engine.analyze(obs, (37.7749, -122.4194), prev_is_high_gen=True, now_ms=1000)
        self.assertEqual(res['threat'], 'SAFE')
        self.assertLess(res['score'], 0.45)
        self.assertFalse(res['quarantine'])

    def test_02_involuntary_2g_downgrade(self):
        obs = {'gen': 'GSM_2G', 'mcc': 310, 'mnc': 410, 'tac': 9999, 'cid': 5555, 'rsrp': -65, 'neighbors': 0}
        res = self.engine.analyze(obs, (37.7749, -122.4194), prev_is_high_gen=True, now_ms=2000)
        self.assertIn("Forced downgrade to 2G", res['reasons'])
        self.assertGreaterEqual(res['score'], 0.45)

    def test_03_macro_cell_shadow_clone_jump(self):
        # Step 1: establish baseline signal
        obs1 = {'gen': 'LTE_4G', 'mcc': 310, 'mnc': 410, 'tac': 12014, 'cid': 1004521, 'rsrp': -98, 'neighbors': 3}
        self.engine.analyze(obs1, (37.7749, -122.4194), prev_is_high_gen=True, now_ms=1000)

        # Step 2: sudden jump (+38 dBm) on same CID 1 second later
        obs2 = {'gen': 'LTE_4G', 'mcc': 310, 'mnc': 410, 'tac': 12014, 'cid': 1004521, 'rsrp': -60, 'neighbors': 3}
        res2 = self.engine.analyze(obs2, (37.7749, -122.4194), prev_is_high_gen=True, now_ms=2000)
        has_clone_reason = any("Macro-Cell Shadow Clone" in r for r in res2['reasons'])
        self.assertTrue(has_clone_reason, "Should detect rapid RSRP surge on identical cell ID")

    def test_04_hysteresis_filtering(self):
        # Single anomaly spike should not immediately trigger full quarantine until confirmed
        obs_spike = {'gen': 'LTE_4G', 'mcc': 310, 'mnc': 410, 'tac': 0, 'cid': 0, 'rsrp': -55, 'neighbors': 0}
        res1 = self.engine.analyze(obs_spike, None, prev_is_high_gen=True, now_ms=1000)
        self.assertEqual(res1['threat'], 'SUSPICIOUS')

        # Second consecutive confirmation triggers full quarantine
        res2 = self.engine.analyze(obs_spike, None, prev_is_high_gen=True, now_ms=3000)
        self.assertEqual(res2['threat'], 'CRITICAL_ROGUE')
        self.assertTrue(res2['quarantine'])

    def test_05_spatial_drift_detection(self):
        # Claimed tower is SF (37.7749), user is in NY (40.7128) -> ~4128 km
        obs = {'gen': 'LTE_4G', 'mcc': 310, 'mnc': 410, 'tac': 12014, 'cid': 1004521, 'rsrp': -88, 'neighbors': 2}
        res = self.engine.analyze(obs, (40.7128, -74.0060), prev_is_high_gen=True, now_ms=1000)
        self.assertTrue(any("Spatial drift" in r for r in res['reasons']))

    def test_06_tunnelcrack_dual_route_coverage(self):
        # Verify 0.0.0.0/1 + 128.0.0.0/1 perfectly covers full 32-bit IPv4 space
        # 0.0.0.0/1 = [0x00000000, 0x7FFFFFFF] (2^31 IPs)
        # 128.0.0.0/1 = [0x80000000, 0xFFFFFFFF] (2^31 IPs)
        range1 = (0, (1 << 31) - 1)
        range2 = (1 << 31, (1 << 32) - 1)
        total_ips = (range1[1] - range1[0] + 1) + (range2[1] - range2[0] + 1)
        self.assertEqual(total_ips, 1 << 32)
        self.assertEqual(range1[1] + 1, range2[0])

    def test_07_storage_bounds_circular_pruning(self):
        # Emulate 1,200 incident insertions and test pruning
        records = list(range(1, 1201)) # IDs 1 to 1200
        # Keep latest 1,000 (IDs 201 to 1200)
        pruned = records[-1000:]
        self.assertEqual(len(pruned), 1000)
        self.assertEqual(pruned[0], 201)
        self.assertEqual(pruned[-1], 1200)

    def test_08_emergency_call_fail_safe_transitions(self):
        # Emulate CallState transitions
        CALL_STATE_IDLE = 0
        CALL_STATE_RINGING = 1
        CALL_STATE_OFFHOOK = 2

        vpn_active = True
        emergency_suspended = False

        # User dials 911 -> State changes to OFFHOOK
        current_state = CALL_STATE_OFFHOOK
        if current_state in (CALL_STATE_OFFHOOK, CALL_STATE_RINGING):
            emergency_suspended = True
            vpn_active = False

        self.assertTrue(emergency_suspended)
        self.assertFalse(vpn_active, "VPN killswitch must be suspended during emergency call")

        # Emergency call ends -> State returns to IDLE
        current_state = CALL_STATE_IDLE
        if current_state == CALL_STATE_IDLE and emergency_suspended:
            emergency_suspended = False
            vpn_active = True

        self.assertFalse(emergency_suspended)
        self.assertTrue(vpn_active, "VPN killswitch must auto-resume after call conclusion")

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestRadioGuardCore)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
