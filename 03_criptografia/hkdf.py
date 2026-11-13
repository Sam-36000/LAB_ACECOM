
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def codificar_secreto(secreto: int, p: int) -> bytes:
    """
    Codifica el secreto compartido en big-endian,
    rellenando con ceros hasta la longitud de p.
    """

    if type(secreto) is not int or type(p) is not int:
        raise ValueError("El secreto y p deben ser enteros.")

    if p <= 1 or not 0 <= secreto < p:
        raise ValueError("Secreto o parametro p invalido.")

    longitud = (p.bit_length() + 7) // 8

    return secreto.to_bytes(longitud, byteorder="big")


def derivar_clave(
    secreto: int,
    p: int,
    salt: bytes = None,
    info: bytes = b"LABO-ACECOM-DH-EXPERIMENT",
    longitud: int = 32
) -> bytes:
    """
    Deriva una clave simetrica mediante HKDF-SHA-256.

    Esta es una derivacion experimental inspirada
    en TLS 1.3, no una implementacion completa
    del key schedule del protocolo.
    """

    if not isinstance(info, bytes):
        raise ValueError("info debe ser de tipo bytes.")

    if not 1 <= longitud <= 255 * 32:
        raise ValueError("Longitud HKDF fuera de rango.")

    secreto_bytes = codificar_secreto(secreto, p)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=longitud,
        salt=salt,
        info=info
    )

    return hkdf.derive(secreto_bytes)


if __name__ == "__main__":

    secreto = 12
    p = 23

    clave = derivar_clave(secreto, p)

    print("\n===== HKDF-SHA-256 =====")
    print("Secreto compartido:", secreto)
    print("Secreto codificado:", codificar_secreto(secreto, p).hex())
    print("Longitud de clave:", len(clave), "bytes")
    print("Clave derivada:", clave.hex())
    print("Derivacion completada correctamente.")
