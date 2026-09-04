import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import BoilerplateCommandSender, CLA, InsType, Errors

# In this tests we check the behavior of the device when asked to sign a transaction

# ML-DSA-87 signing context: "ZOND" || version 0x01 || descriptor 01 00 00
SIGNING_CONTEXT = bytes.fromhex("5a4f4e4401010000")
PK_LEN = 2592
SIG_LEN = 4627


def get_public_key_chunks(backend: BackendInterface) -> bytes:
    """Fetch the 2,592-byte ML-DSA-87 public key via chunked GET_PUBLIC_KEY."""
    pk = b""
    for p2 in range(1, 12):
        r = backend.exchange(cla=CLA, ins=InsType.GET_PUBLIC_KEY, p1=0, p2=p2)
        pk += r.data
    return pk[:PK_LEN]


def get_signature_chunks(backend: BackendInterface, first_chunk: bytes) -> bytes:
    """Collect the remaining signature chunks after the auto-returned first."""
    sig = bytearray(first_chunk)
    for p2 in range(1, 18):
        r = backend.exchange(cla=CLA, ins=InsType.SIGN_TX, p1=2, p2=p2)
        sig += r.data
    return bytes(sig)[:SIG_LEN]


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_short_tx(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # The path used for this entire test
    path: str = "m/44'/238'/0'/0/0"

    # Derive the key on-device and fetch the public key for verification
    client.get_public_key(path=path)
    public_key = get_public_key_chunks(backend)

    # Unsigned go-qrl sighash preimage (11 RLP fields)
    # RLP: type=02, chain_id=1, nonce=3, gas_tip_cap, gas_fee_cap, gas=25000,
    #      to=b94f...aaaa (64 bytes), value, data, access_list=empty,
    #      descriptor=[0x01, 0x00, 0x00] (ML-DSA-87), extra_params=empty
    transaction = bytes.fromhex("02f86201038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a000080c08301000080")

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(path=path, transaction=transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        scenario_navigator.review_approve()

    # Collect the full detached signature and verify it independently:
    # the device signs keccak256(preimage) under the fixed 8-byte context.
    signature = get_signature_chunks(backend, client.get_async_response().data)
    assert len(signature) == SIG_LEN
    sighash = keccak.new(digest_bits=256, data=transaction).digest()
    assert ML_DSA_87.verify(public_key, sighash, signature, ctx=SIGNING_CONTEXT)
    # Tampered message must not verify
    assert not ML_DSA_87.verify(public_key, b"\x00" * 32, signature, ctx=SIGNING_CONTEXT)

# In this test we send to the device a transaction to trig a blind-signing flow
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
# def test_sign_tx_short_tx_blind_sign(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
#     # Use the app interface instead of raw interface
#     client = BoilerplateCommandSender(backend)
#     # The path used for this entire test
#     path: str = "m/44'/238'/0'/0/0"

#     # Create the transaction that will be sent to the device for signing
#     # transaction = Transaction(
#     #     nonce=1,
#     #     to="0x0000000000000000000000000000000000000000",
#     #     value=0,
#     #     memo="Blind-sign"
#     # ).serialize()
#     transaction = bytes.fromhex("aabbccddee")

#     # As it requires on-screen validation, the function is asynchronous.
#     # It will yield the result when the navigation is done
#     with client.sign_tx(path=path, transaction=transaction):
#         # Validate the on-screen request by performing the navigation appropriate for this device
#         scenario_navigator.review_approve_with_warning(warning_path="part1")

#     # The device as yielded the result, parse it and ensure that the signature is correct
#     response = client.get_async_response().data
#     print(response.hex())
#     # _, der_sig, _ = unpack_sign_tx_response(response)
#     # assert check_signature_validity(public_key, der_sig, transaction)
#     assert True

# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    path: str = "m/44'/238'/0'/0/0"

    # Unsigned go-qrl sighash preimage with 64-byte recipient
    transaction = bytes.fromhex("02f86201038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a000080c08301000080")

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(path=path, transaction=transaction):
            scenario_navigator.review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0


def test_calldata_refused_when_blind_signing_disabled(backend: BackendInterface) -> None:
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    # Same transaction as the clear-signing case, but data is the non-empty 0x5544.
    transaction = bytes.fromhex("02f86401038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a0000825544c08301000080")
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_oversized_tx_rejected_across_multiple_apdus(backend: BackendInterface) -> None:
    """Stream a transaction larger than MAX_TRANSACTION_LEN (510 bytes).

    This is the only test that drives the multi-APDU reassembly path: at 600
    bytes the client splits the payload into three chunks, so the P1=DATA_MORE
    branch runs twice before the accumulated length guard in handler_sign_tx
    trips. The guard fires during streaming, before any RLP parsing or UI, so
    the payload does not need to be a well-formed transaction.
    """
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    transaction = bytes([0x02]) + b"\xaa" * 599  # 600 B > 510 B buffer
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_WRONG_TX_LENGTH


def test_tx_at_max_length_is_parsed_not_length_rejected(backend: BackendInterface) -> None:
    """A 510-byte payload must reach the parser rather than the length guard.

    Guards against an off-by-one that would reject transactions at exactly
    MAX_TRANSACTION_LEN. The payload is deliberately not valid RLP, so the
    expected outcome is a parsing failure - proving the length check passed.
    """
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    transaction = bytes([0x02]) + b"\xaa" * 509  # exactly 510 B
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_TX_PARSING_FAIL
