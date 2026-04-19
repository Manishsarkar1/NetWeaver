import json
import unittest

from vanta_core.vip_mapping import InMemoryVIPMapper, RedisBackedVIPMapper


class FakeClock:
    def __init__(self, start=0):
        self.current = start

    def now(self):
        return self.current

    def advance(self, seconds):
        self.current += seconds


class FakeRedisClient:
    def __init__(self, time_fn):
        self._time_fn = time_fn
        self._store = {}

    def ping(self):
        return True

    def set(self, key, value, ex=None):
        expires_at = None if ex is None else self._time_fn() + ex
        self._store[key] = {"value": value, "expires_at": expires_at}
        return True

    def get(self, key):
        self._purge_expired()
        entry = self._store.get(key)
        if entry is None:
            return None
        return entry["value"]

    def scan_iter(self, match=None):
        self._purge_expired()
        prefix = (match or "").rstrip("*")
        for key in sorted(self._store):
            if not match or key.startswith(prefix):
                yield key

    def _purge_expired(self):
        now = self._time_fn()
        expired = [
            key
            for key, entry in self._store.items()
            if entry["expires_at"] is not None and entry["expires_at"] <= now
        ]
        for key in expired:
            del self._store[key]


class InMemoryVIPMapperTests(unittest.TestCase):
    def test_allocate_and_rotate_uses_next_available_vip(self):
        mapper = InMemoryVIPMapper(
            vip_pool=[
                "192.168.100.1",
                "192.168.100.2",
                "192.168.100.3",
            ]
        )

        vip, created = mapper.ensure_vip("10.0.0.1")
        self.assertTrue(created)
        self.assertEqual(vip, "192.168.100.1")

        old_vip, new_vip = mapper.rotate_vip("10.0.0.1")
        self.assertEqual(old_vip, "192.168.100.1")
        self.assertEqual(new_vip, "192.168.100.2")


class RedisBackedVIPMapperTests(unittest.TestCase):
    def test_restore_rehydrates_unexpired_mappings(self):
        clock = FakeClock(start=100)
        client = FakeRedisClient(clock.now)
        client.set(
            "vanta:test:mapping:10.0.0.9",
            json.dumps(
                {
                    "real_ip": "10.0.0.9",
                    "vip": "192.168.100.44",
                    "updated_at": clock.now(),
                }
            ),
            ex=30,
        )

        mapper = RedisBackedVIPMapper(
            client,
            key_prefix="vanta:test",
            time_fn=clock.now,
        )

        self.assertEqual(mapper.restored_count, 1)
        self.assertEqual(mapper.get_vip("10.0.0.9"), "192.168.100.44")

    def test_refresh_all_extends_redis_ttl(self):
        clock = FakeClock()
        client = FakeRedisClient(clock.now)
        mapper = RedisBackedVIPMapper(
            client,
            key_prefix="vanta:test",
            vip_pool=["192.168.100.1"],
            time_fn=clock.now,
        )

        mapper.ensure_vip("10.0.0.1", ttl_seconds=10)
        key = "vanta:test:mapping:10.0.0.1"

        clock.advance(9)
        self.assertIsNotNone(client.get(key))

        mapper.refresh_all(ttl_seconds=10)
        clock.advance(9)
        self.assertIsNotNone(client.get(key))

        clock.advance(2)
        self.assertIsNone(client.get(key))


if __name__ == "__main__":
    unittest.main()
