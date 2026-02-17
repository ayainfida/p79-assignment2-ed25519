import json
import unittest
from ed25519 import ED25519, ED25519ScalarMultAlgorithm, PublicKey, Signature, Message

class TestWycheProof(unittest.TestCase):
    def setUp(self):
        self.ed25519 = ED25519()
        self.ed25519_fast = ED25519(ED25519ScalarMultAlgorithm.FAST_SCALAR_MULT) 
        with open("tests/json/project_wyche_proof_ed25519_test.json") as f:
            self.data = json.load(f)

    """
    Helper method to set up test metadata for a given test case.
    """
    def _set_test_metadata(self, pk: PublicKey, msg: Message, sig: Signature, result: bool) -> dict:
        return {
            'pk': pk,
            'msg': msg,
            'sig': sig,
            'result': result
        }
    
    def _test_vector(self, metadata: dict, ed25519_instance: ED25519):
        pk = metadata['pk']
        msg = metadata['msg']
        sig = metadata['sig']
        expected = metadata['result']

        # Test signature verification
        try:
            verification_result = ed25519_instance.verify(msg, sig, pk)
        except ValueError:
            verification_result = False
        
        # Check if the signature verification returns the expected result        
        self.assertEqual(verification_result, expected)
    
    """
    Test vectors from Wycheproof project for Ed25519 signature verification.
    These tests give a public key, message, and signature as input, along with the expected result of whether the signature should be valid or not.
    https://github.com/C2SP/wycheproof
    """
    def _test_wycheproof_vectors(self, ed25519_instance: ED25519):
        for group in self.data["testGroups"]:
            pk = PublicKey(bytes.fromhex(group["publicKey"]["pk"]))
            for t in group["tests"]:
                msg = Message(bytes.fromhex(t["msg"]))
                sig = Signature(bytes.fromhex(t["sig"]))
                expected = (t["result"] == "valid")

                metadata = self._set_test_metadata(pk=pk, msg=msg, sig=sig, result=expected)

                self._test_vector(metadata, ed25519_instance)

    def test_wycheproof_vectors(self):
        self._test_wycheproof_vectors(self.ed25519)

    def test_wycheproof_vectors_fast(self):
        self._test_wycheproof_vectors(self.ed25519_fast)

if __name__ == "__main__":
    unittest.main()