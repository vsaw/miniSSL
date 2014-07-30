import unittest
import minissl.keyutils as keyutils
import minissl.Utils as Utils


class TestUtils(unittest.TestCase):
    def test_is_valid_nonce(self):
        self.assertTrue(Utils.is_valid_nonce(keyutils.generate_nonce()))
        self.assertFalse(Utils.is_valid_nonce('string'))
        self.assertFalse(Utils.is_valid_nonce(self))

    def test_padding_rfc5652_round_trip(self):
        data = 'hi there!'
        padded_data = Utils.padd_rfc5652(data)
        unpadded_data = Utils.unpad_rfc5653(padded_data)
        self.assertEqual(0, len(padded_data) % 16)
        self.assertEqual(16, len(padded_data))
        self.assertEqual(data, unpadded_data)
        self.assertEqual('hi there!\x07\x07\x07\x07\x07\x07\x07', padded_data)

    def test_padding_rfc5652_round_trip_block_size(self):
        data = '0123456789abcdef'
        padded_data = Utils.padd_rfc5652(data)
        unpadded_data = Utils.unpad_rfc5653(padded_data)
        self.assertEqual(0, len(padded_data) % 16)
        self.assertEqual(32, len(padded_data))
        self.assertEqual(data, unpadded_data)
        self.assertEqual(
            '0123456789abcdef\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10',
            padded_data)

    def test_aes_hmac_roundtrip_success(self):
        data = 'im concerned about my privacy!'
        aes_key = keyutils.generate_random(16)
        hmac_key = keyutils.generate_random(32)
        (encrypted_msg, iv, hmac) = Utils.aes_128_hmac_encrypt(data, aes_key,
                                                               hmac_key)
        decrypted_data = Utils.aes_128_hmac_decrypt_verify(encrypted_msg, hmac,
                                                           aes_key, iv,
                                                           hmac_key)
        self.assertEqual(data, decrypted_data)

    def test_aes_hmac_roundtrip_fail(self):
        data = 'im concerned about my privacy!'
        aes_key = keyutils.generate_random(16)
        hmac_key = keyutils.generate_random(32)
        (encrypted_msg, iv, hmac) = Utils.aes_128_hmac_encrypt(data, aes_key,
                                                               hmac_key)
        # change the key after encryption to cause a decryption failure
        aes_key = keyutils.generate_random(16)
        decrypted_data = Utils.aes_128_hmac_decrypt_verify(encrypted_msg, hmac,
                                                           aes_key, iv,
                                                           hmac_key)
        self.assertIsNone(decrypted_data)
