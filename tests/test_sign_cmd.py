import pytest

from Crypto.Hash import keccak
from dilithium_py.ml_dsa import ML_DSA_87
from ledgered.devices import Device
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator, NavIns, NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender, CLA, InsType, Errors, MAX_APDU_LEN,
)

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


# --- streaming parser: the device no longer buffers the whole transaction -----

# Fields of the preimage used in test_sign_tx_short_tx, so that a transaction
# with arbitrary calldata can be built without a separate vector generator.
_CHAIN_ID = bytes.fromhex("01")
_NONCE = bytes.fromhex("03")
_GAS_TIP_CAP = bytes.fromhex("77359400")
_GAS_FEE_CAP = bytes.fromhex("0ba43b7400")
_GAS = bytes.fromhex("61a8")
_TO = bytes.fromhex("b94f5374fce5edbc8e2a8697c15331677e6ebf0b" + "aa" * 44)
_VALUE = bytes.fromhex("016345785d8a0000")
_DESCRIPTOR = bytes.fromhex("010000")
_REFERENCE_PREIMAGE = bytes.fromhex("02f86201038477359400850ba43b74008261a8b840b94f5374fce5edbc8e2a8697c15331677e6ebf0baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88016345785d8a000080c08301000080")


def _rlp_len(base: int, n: int) -> bytes:
    if n < 56:
        return bytes([base + n])
    length = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([base + 55 + len(length)]) + length


def _rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _rlp_len(0x80, len(b)) + b


def build_preimage(data: bytes, access_list: bytes = b"\xc0") -> bytes:
    """Build the 11-field preimage; access_list is an already RLP-encoded list."""
    payload = b"".join(_rlp_bytes(f) for f in (_CHAIN_ID, _NONCE, _GAS_TIP_CAP, _GAS_FEE_CAP, _GAS, _TO, _VALUE, data))
    payload += access_list + _rlp_bytes(_DESCRIPTOR) + b"\x80"
    return b"\x02" + _rlp_len(0xc0, len(payload)) + payload


def enable_blind_signing(device: Device, navigator: Navigator) -> None:
    """Enable the setting through the same UI a user must navigate."""
    if device.is_nano:
        for text in ("App settings", "Blind signing", "Back"):
            navigator.navigate_until_text(
                NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                text=text,
                screen_change_before_first_instruction=False,
            )
    else:
        navigator.navigate(
            [
                NavInsID.USE_CASE_HOME_SETTINGS,
                NavIns(NavInsID.TOUCH, (200, 113)),  # First setting: Blind signing.
                NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT,
            ],
            screen_change_before_first_instruction=False,
        )


@pytest.mark.parametrize("payload_field", ["calldata", "access_list"])
def test_sign_tx_large_payload(backend: BackendInterface,
                               device: Device,
                               navigator: Navigator,
                               scenario_navigator: NavigateWithScenario,
                               payload_field: str) -> None:
    """Sign a multi-APDU transaction and verify every streamed byte was hashed."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    enable_blind_signing(device, navigator)
    client.get_public_key(path=path)
    public_key = get_public_key_chunks(backend)
    assert len(public_key) == PK_LEN

    if payload_field == "calldata":
        transaction = build_preimage(bytes(range(256)) * 12)
    else:
        # One 64-byte address with 96 distinct 32-byte storage keys. Both
        # skipped fields must contribute to the sighash without being buffered.
        keys = b"".join(_rlp_bytes(i.to_bytes(32, "big")) for i in range(96))
        entry = _rlp_bytes(_TO) + _rlp_len(0xc0, len(keys)) + keys
        entries = _rlp_len(0xc0, len(entry)) + entry
        transaction = build_preimage(b"", _rlp_len(0xc0, len(entries)) + entries)
    assert len(transaction) > 3000

    with client.sign_tx(path=path, transaction=transaction):
        scenario_navigator.review_approve_with_warning(do_comparison=False)

    response = client.get_async_response()
    assert response is not None
    signature = get_signature_chunks(backend, response.data)
    assert len(signature) == SIG_LEN
    sighash = keccak.new(digest_bits=256, data=transaction).digest()
    assert ML_DSA_87.verify(public_key, sighash, signature, ctx=SIGNING_CONTEXT)

    # Change a byte in the skipped payload beyond the former 510-byte limit.
    tampered = bytearray(transaction)
    tampered[2 * MAX_APDU_LEN] ^= 1
    tampered_hash = keccak.new(digest_bits=256, data=tampered).digest()
    assert not ML_DSA_87.verify(public_key, tampered_hash, signature, ctx=SIGNING_CONTEXT)


def test_preimage_builder_matches_reference() -> None:
    assert build_preimage(b"") == _REFERENCE_PREIMAGE


def test_malformed_tx_rejected_while_streaming(backend: BackendInterface) -> None:
    """600 bytes of garbage split by the client into three APDUs.

    The streaming parser rejects the payload on the first chunk (0xaa is not
    an RLP list header), before any later APDU, any UI and without a buffer
    size limit: the former 510-byte limit and SW_WRONG_TX_LENGTH are gone.
    """
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    transaction = bytes([0x02]) + b"\xaa" * 599
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_TX_PARSING_FAIL


def test_large_calldata_refused_when_blind_signing_disabled(backend: BackendInterface) -> None:
    """A 3 kB calldata is streamed over 13 APDUs and decoded to the end.

    Blind signing is off by default, so the device refuses once the whole
    transaction has been parsed. Before the streaming parser the same payload
    was rejected on the third APDU by the 510-byte buffer limit, so SW_DENY
    here proves the limit is gone and the parser kept its position across
    all chunks.
    """
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    transaction = build_preimage(b"\xab" * 3000)
    assert len(transaction) > 3000
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=transaction):
            pass
    assert exc.value.status == Errors.SW_DENY


def test_truncated_tx_rejected(backend: BackendInterface) -> None:
    """The last APDU arrives before the outer RLP list is complete."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=_REFERENCE_PREIMAGE[:-1]):
            pass
    assert exc.value.status == Errors.SW_TX_PARSING_FAIL


def test_trailing_bytes_rejected(backend: BackendInterface) -> None:
    """Bytes after the end of the outer RLP list must not be signed."""
    client = BoilerplateCommandSender(backend)
    path = "m/44'/238'/0'/0/0"
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.sign_tx(path=path, transaction=_REFERENCE_PREIMAGE + b"\x00"):
            pass
    assert exc.value.status == Errors.SW_TX_PARSING_FAIL
