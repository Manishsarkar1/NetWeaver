import unittest

from vanta_core.defense import MorphingStrategy, ThreatDetector


class FakeClock:
    def __init__(self, start=0):
        self.current = start

    def now(self):
        return self.current

    def advance(self, seconds):
        self.current += seconds


class MorphingStrategyTests(unittest.TestCase):
    def test_time_based_morph_respects_interval(self):
        clock = FakeClock(start=100)
        strategy = MorphingStrategy(time_fn=clock.now)
        strategy.time_based = True
        strategy.time_interval = 30

        self.assertTrue(strategy.should_morph_time_based("10.0.0.1", "10.0.0.2"))
        self.assertFalse(strategy.should_morph_time_based("10.0.0.1", "10.0.0.2"))

        clock.advance(30)
        self.assertTrue(strategy.should_morph_time_based("10.0.0.1", "10.0.0.2"))

    def test_packet_count_trigger_resets_counter(self):
        strategy = MorphingStrategy()
        strategy.packet_count_based = True
        strategy.packet_threshold = 3

        for _ in range(3):
            strategy.record_packet("10.0.0.1", "10.0.0.2")

        self.assertTrue(strategy.should_morph_packet_count("10.0.0.1", "10.0.0.2"))
        self.assertFalse(strategy.should_morph_packet_count("10.0.0.1", "10.0.0.2"))

    def test_pair_key_is_order_independent(self):
        strategy = MorphingStrategy()

        self.assertEqual(
            strategy._pair_key("10.0.0.1", "10.0.0.2"),
            strategy._pair_key("10.0.0.2", "10.0.0.1"),
        )


class ThreatDetectorTests(unittest.TestCase):
    def test_port_scan_detection_triggers_at_threshold(self):
        clock = FakeClock()
        debug_lines = []
        detector = ThreatDetector(
            time_fn=clock.now,
            now_fn=lambda: "2026-03-27 23:59:59",
            debug_sink=debug_lines.append,
        )
        detector.port_scan_threshold = 3

        self.assertFalse(detector.detect_port_scan("1.1.1.1", "10.0.0.2", 22))
        self.assertFalse(detector.detect_port_scan("1.1.1.1", "10.0.0.2", 80))
        self.assertTrue(detector.detect_port_scan("1.1.1.1", "10.0.0.2", 443))

        self.assertEqual(len(detector.threats), 1)
        self.assertIn("PORT SCAN DETECTED", debug_lines[-1])

    def test_scan_window_reset_allows_clean_restart(self):
        clock = FakeClock()
        detector = ThreatDetector(time_fn=clock.now, debug_sink=lambda _: None)
        detector.port_scan_threshold = 3
        detector.port_scan_window = 5

        detector.detect_port_scan("1.1.1.1", "10.0.0.2", 22)
        clock.advance(6)
        detector.detect_port_scan("1.1.1.1", "10.0.0.2", 80)
        self.assertEqual(len(detector.threats), 0)

    def test_detect_port_scan_keeps_threat_history(self):
        clock = FakeClock()
        detector = ThreatDetector(time_fn=clock.now, debug_sink=lambda _: None)
        detector.port_scan_threshold = 2

        detector.detect_port_scan("1.1.1.1", "10.0.0.2", 22)
        detector.detect_port_scan("1.1.1.1", "10.0.0.2", 80)

        self.assertEqual(len(detector.threats), 1)
        self.assertEqual(detector.threats[0].threat_type, "port_scan")


if __name__ == "__main__":
    unittest.main()
