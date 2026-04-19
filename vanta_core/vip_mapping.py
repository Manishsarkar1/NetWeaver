import json
import threading
import time


try:
    import redis
except ImportError:  # pragma: no cover - exercised only when optional dependency is missing
    redis = None


def build_default_vip_pool():
    return [f"192.168.100.{i}" for i in range(1, 255)]


class InMemoryVIPMapper:
    """Maintains active VIP assignments for the running controller instance."""

    backend_name = "memory"
    persistence_enabled = False

    def __init__(self, vip_pool=None, time_fn=None):
        self._lock = threading.RLock()
        self._time_fn = time_fn or time.time
        self._all_vips = tuple(vip_pool or build_default_vip_pool())
        self._available_vips = set(self._all_vips)
        self._real_to_virtual = {}
        self._virtual_to_real = {}
        self.restored_count = 0

    def has_mapping(self, real_ip):
        with self._lock:
            return real_ip in self._real_to_virtual

    def get_vip(self, real_ip):
        with self._lock:
            return self._real_to_virtual.get(real_ip)

    def ensure_vip(self, real_ip, ttl_seconds=None):
        with self._lock:
            vip = self._real_to_virtual.get(real_ip)
            if vip is not None:
                self._persist_mapping(real_ip, vip, ttl_seconds)
                return vip, False

            vip = self._take_next_vip()
            if vip is None:
                return None, False

            self._real_to_virtual[real_ip] = vip
            self._virtual_to_real[vip] = real_ip
            self._persist_mapping(real_ip, vip, ttl_seconds)
            return vip, True

    def rotate_vip(self, real_ip, ttl_seconds=None):
        with self._lock:
            old_vip = self._real_to_virtual.get(real_ip)
            if old_vip is None:
                return None, None

            self._available_vips.add(old_vip)
            del self._virtual_to_real[old_vip]

            new_vip = self._take_next_vip(excluded={old_vip})
            if new_vip is None:
                new_vip = old_vip
                self._available_vips.discard(old_vip)

            self._real_to_virtual[real_ip] = new_vip
            self._virtual_to_real[new_vip] = real_ip
            self._persist_mapping(real_ip, new_vip, ttl_seconds)
            return old_vip, new_vip

    def refresh_mapping(self, real_ip, ttl_seconds=None):
        with self._lock:
            vip = self._real_to_virtual.get(real_ip)
            if vip is None:
                return False

            self._persist_mapping(real_ip, vip, ttl_seconds)
            return True

    def refresh_all(self, ttl_seconds=None):
        with self._lock:
            for real_ip, vip in self._real_to_virtual.items():
                self._persist_mapping(real_ip, vip, ttl_seconds)

    def list_real_ips(self):
        with self._lock:
            return list(self._real_to_virtual.keys())

    def list_mappings(self):
        with self._lock:
            return list(self._real_to_virtual.items())

    def seed_mapping(self, real_ip, vip):
        with self._lock:
            if vip not in self._available_vips or real_ip in self._real_to_virtual:
                return False
            self._real_to_virtual[real_ip] = vip
            self._virtual_to_real[vip] = real_ip
            self._available_vips.remove(vip)
            return True

    def _take_next_vip(self, excluded=None):
        candidates = self._available_vips.difference(excluded or set())
        if not candidates:
            candidates = self._available_vips
        if not candidates:
            return None

        vip = min(candidates, key=self._vip_sort_key)
        self._available_vips.remove(vip)
        return vip

    @staticmethod
    def _vip_sort_key(vip):
        return tuple(int(part) for part in vip.split("."))

    def _persist_mapping(self, real_ip, vip, ttl_seconds):
        return None


class RedisBackedVIPMapper(InMemoryVIPMapper):
    """Adds Redis-backed persistence for crash recovery without changing live controller semantics."""

    backend_name = "redis"
    persistence_enabled = True

    def __init__(self, redis_client, key_prefix="vanta:vip", vip_pool=None, time_fn=None):
        super().__init__(vip_pool=vip_pool, time_fn=time_fn)
        self._redis = redis_client
        self._key_prefix = key_prefix.rstrip(":")
        self.restored_count = self._restore_mappings()

    def _mapping_key(self, real_ip):
        return f"{self._key_prefix}:mapping:{real_ip}"

    def _persist_mapping(self, real_ip, vip, ttl_seconds):
        ttl_seconds = max(1, int(ttl_seconds or 1))
        payload = json.dumps(
            {
                "real_ip": real_ip,
                "vip": vip,
                "updated_at": self._time_fn(),
            }
        )
        self._redis.set(self._mapping_key(real_ip), payload, ex=ttl_seconds)

    def _restore_mappings(self):
        restored = 0
        pattern = f"{self._key_prefix}:mapping:*"
        for key in self._redis.scan_iter(match=pattern):
            raw = self._redis.get(key)
            if not raw:
                continue

            try:
                payload = json.loads(raw)
            except (TypeError, ValueError):
                continue

            real_ip = payload.get("real_ip")
            vip = payload.get("vip")
            if not real_ip or not vip or vip not in self._available_vips:
                continue

            self._real_to_virtual[real_ip] = vip
            self._virtual_to_real[vip] = real_ip
            self._available_vips.remove(vip)
            restored += 1

        return restored


def build_vip_mapper(config):
    backend = (config.vip_mapping_backend or "memory").lower()
    if backend == "memory":
        return InMemoryVIPMapper()

    if backend != "redis":
        raise ValueError(f"Unsupported VIP mapping backend: {backend}")

    if redis is None:
        raise RuntimeError(
            "Redis backend requested but the 'redis' package is not installed."
        )

    client = redis.from_url(
        config.redis_url,
        decode_responses=True,
        socket_timeout=config.redis_socket_timeout_seconds,
    )
    client.ping()
    return RedisBackedVIPMapper(client, key_prefix=config.redis_key_prefix)
