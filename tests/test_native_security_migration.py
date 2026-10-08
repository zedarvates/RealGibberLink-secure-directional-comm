"""Run against a built PyO3 extension: REALGIBBER_CORE_LIBRARY=/path/to/lib.so."""
import importlib.util
import os
import time
import unittest


def load_core():
    path = os.environ.get("REALGIBBER_CORE_LIBRARY")
    if path:
        spec = importlib.util.spec_from_file_location("_core", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    from realgibber import _core
    return _core


core = load_core()


class NativeSecurityMigrationTests(unittest.TestCase):
    def test_crypto_roundtrip_and_tamper_rejection(self):
        key = core.PyCryptoEngine.generate_secure_random_bytes(32)
        encrypted = core.PyCryptoEngine.encrypt_data(key, b"security migration")
        self.assertEqual(bytes(core.PyCryptoEngine.decrypt_data(key, encrypted)), b"security migration")
        encrypted = list(encrypted)
        encrypted[-1] ^= 1
        with self.assertRaises(RuntimeError):
            core.PyCryptoEngine.decrypt_data(key, encrypted)

    def test_minimum_policy_denies_commands(self):
        manager = core.PySecurityManager("Minimum")
        manager.check_permission("Discussion", "Single")
        with self.assertRaisesRegex(RuntimeError, "Permission"):
            manager.check_permission("Command", "Single")

    def test_locked_policy_denies_without_grant(self):
        manager = core.PySecurityManager("Locked")
        with self.assertRaisesRegex(RuntimeError, "Permission"):
            manager.check_permission("Discussion", "Session")

    def test_invalid_pin_remains_rejected(self):
        manager = core.PySecurityManager("Locked")
        with self.assertRaises(RuntimeError):
            manager.validate_pin("wrong")

    def test_invalid_policy_names_are_rejected(self):
        with self.assertRaises(RuntimeError):
            core.PySecurityManager("typo")
        manager = core.PySecurityManager("Minimum")
        for permission, scope in [("typo", "Single"), ("Discussion", "typo")]:
            with self.assertRaises(RuntimeError):
                manager.check_permission(permission, scope)

    def test_async_state_survives_python_calls(self):
        detector = core.PyRangeDetector()
        detector.initialize()
        laser = core.PyLaserEngine("Visible", "OOK", 5.0, 100.0)
        laser.enable_adaptive_mode(detector)
        laser.initialize()
        self.assertIsInstance(laser.get_alignment_status().beam_position_x, float)
        for samples in [0, 1001]:
            with self.assertRaises(RuntimeError):
                detector.measure_distance_averaged(samples)
        core.PyUltrasonicBeamEngine().initialize()
        self.assertIsNone(core.PyPerformanceMonitor(10).get_current_metrics())

    def test_channel_timestamp_validation(self):
        for timestamp in [float("nan"), float("inf"), -1.0, time.time() + 3600]:
            with self.assertRaises(RuntimeError):
                core.PyChannelData("Laser", [1, 2], timestamp, 1)
        data = core.PyChannelData("Laser", [1, 2], time.time() - 0.01, 1)
        core.PyChannelValidator().receive_channel_data(data)

    @unittest.skipUnless(hasattr(core, "PyPostQuantumEngine"), "post-quantum feature disabled")
    def test_post_quantum_exchange_and_signature(self):
        alice = core.PyPostQuantumEngine()
        bob = core.PyPostQuantumEngine()
        ciphertext = alice.encapsulate_secret(bob.kyber_public_key())
        self.assertEqual(bytes(ciphertext.shared_secret), bytes(bob.decapsulate_secret(ciphertext)))
        signature = alice.sign_data(b"authenticated message")
        self.assertTrue(bob.verify_signature(b"authenticated message", signature, alice.dilithium_public_key()))
        self.assertFalse(bob.verify_signature(b"tampered message", signature, alice.dilithium_public_key()))
        for bad_key in [[], [0] * 1183]:
            with self.assertRaises(RuntimeError):
                alice.encapsulate_secret(bad_key)


if __name__ == "__main__":
    unittest.main()
