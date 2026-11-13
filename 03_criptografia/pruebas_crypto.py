
import pytest

from cryptography.exceptions import InvalidTag

from hkdf import codificar_secreto, derivar_clave
from aes_gcm import cifrar_mensaje, descifrar_mensaje


SECRETO = 12
PRIMO = 23

MENSAJE = "Laboratorio experimental de criptografia cuantica."

AAD = b"LABO-ACECOM-TEST"

NONCE = bytes.fromhex("000000000000000000000001")


def obtener_clave():
    return derivar_clave(SECRETO, PRIMO)


def test_codificacion_secreto():

    resultado = codificar_secreto(SECRETO, PRIMO)

    assert resultado == b"\x0c"
    assert len(resultado) == 1


def test_derivacion_clave():

    clave = obtener_clave()

    assert isinstance(clave, bytes)
    assert len(clave) == 32


def test_derivacion_reproducible():

    clave1 = derivar_clave(SECRETO, PRIMO)
    clave2 = derivar_clave(SECRETO, PRIMO)

    assert clave1 == clave2


def test_cifrado_aes_gcm():

    clave = obtener_clave()

    resultado = cifrar_mensaje(
        clave,
        MENSAJE,
        aad=AAD,
        nonce=NONCE
    )

    assert len(resultado["nonce"]) == 12
    assert len(resultado["tag"]) == 16
    assert resultado["ciphertext"] != b""


def test_descifrado_correcto():

    clave = obtener_clave()

    resultado = cifrar_mensaje(
        clave,
        MENSAJE,
        aad=AAD,
        nonce=NONCE
    )

    recuperado = descifrar_mensaje(
        clave,
        resultado["nonce"],
        resultado["ciphertext"],
        resultado["tag"],
        resultado["aad"]
    )

    assert recuperado == MENSAJE


def test_rechazar_clave_incorrecta():

    clave = obtener_clave()

    resultado = cifrar_mensaje(
        clave,
        MENSAJE,
        aad=AAD,
        nonce=NONCE
    )

    clave_incorrecta = bytes([0] * 32)

    with pytest.raises(ValueError):
        descifrar_mensaje(
            clave_incorrecta,
            resultado["nonce"],
            resultado["ciphertext"],
            resultado["tag"],
            resultado["aad"]
        )


def test_rechazar_tag_modificado():

    clave = obtener_clave()

    resultado = cifrar_mensaje(
        clave,
        MENSAJE,
        aad=AAD,
        nonce=NONCE
    )

    tag_modificado = bytes([0] * 16)

    with pytest.raises(ValueError):
        descifrar_mensaje(
            clave,
            resultado["nonce"],
            resultado["ciphertext"],
            tag_modificado,
            resultado["aad"]
        )


def test_rechazar_mensaje_modificado():

    clave = obtener_clave()

    resultado = cifrar_mensaje(
        clave,
        MENSAJE,
        aad=AAD,
        nonce=NONCE
    )

    ciphertext_modificado = (
        bytes([resultado["ciphertext"][0] ^ 1])
        + resultado["ciphertext"][1:]
    )

    with pytest.raises(ValueError):
        descifrar_mensaje(
            clave,
            resultado["nonce"],
            ciphertext_modificado,
            resultado["tag"],
            resultado["aad"]
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
