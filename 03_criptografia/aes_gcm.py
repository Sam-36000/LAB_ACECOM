
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def cifrar_mensaje(
    clave: bytes,
    mensaje: str,
    aad: bytes = b"",
    nonce: bytes = None
) -> dict:
    """
    Cifra un mensaje usando AES-256-GCM.

    Devuelve nonce, ciphertext y tag por separado.
    """

    if len(clave) != 32:
        raise ValueError("AES-256 requiere una clave de 32 bytes.")

    if not isinstance(mensaje, str):
        raise ValueError("El mensaje debe ser texto.")

    if not isinstance(aad, bytes):
        raise ValueError("AAD debe ser de tipo bytes.")

    if nonce is None:
        nonce = secrets.token_bytes(12)

    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("El nonce debe tener exactamente 12 bytes.")

    aesgcm = AESGCM(clave)

    datos = aesgcm.encrypt(
        nonce,
        mensaje.encode("utf-8"),
        aad
    )

    ciphertext = datos[:-16]
    tag = datos[-16:]

    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
        "aad": aad
    }


def descifrar_mensaje(
    clave: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes = b""
) -> str:
    """
    Descifra y verifica la autenticidad mediante AES-GCM.
    """

    if len(clave) != 32:
        raise ValueError("La clave debe tener 32 bytes.")

    if len(nonce) != 12:
        raise ValueError("Nonce invalido.")

    if len(tag) != 16:
        raise ValueError("La etiqueta debe tener 16 bytes.")

    aesgcm = AESGCM(clave)

    try:
        datos = ciphertext + tag

        mensaje = aesgcm.decrypt(
            nonce,
            datos,
            aad
        )

        return mensaje.decode("utf-8")

    except InvalidTag:
        raise ValueError(
            "AUTENTICACION FALLIDA: clave, nonce, "
            "mensaje, AAD o etiqueta incorrectos."
        )


if __name__ == "__main__":

    from hkdf import derivar_clave

    clave = derivar_clave(12, 23)

    mensaje = (
        "La seguridad de las comunicaciones "
        "depende de la proteccion de las claves."
    )

    resultado = cifrar_mensaje(clave, mensaje)

    print("\n===== AES-256-GCM =====")
    print("Mensaje original:", mensaje)
    print("Nonce:", resultado["nonce"].hex())
    print("Ciphertext:", resultado["ciphertext"].hex())
    print("Tag:", resultado["tag"].hex())

    recuperado = descifrar_mensaje(
        clave,
        resultado["nonce"],
        resultado["ciphertext"],
        resultado["tag"],
        resultado["aad"]
    )

    print("Mensaje recuperado:", recuperado)
    print("Descifrado correcto:", recuperado == mensaje)
