
from dataclasses import dataclass
from sympy import isprime


@dataclass(frozen=True)
class DHParameters:
    """Parametros publicos de Diffie-Hellman."""
    p: int
    q: int
    g: int


def validar_parametros(params: DHParameters) -> bool:
    """Valida matematicamente los parametros del subgrupo."""

    p = params.p
    q = params.q
    g = params.g

    # 1. Validar que sean enteros
    if not all(type(v) is int for v in (p, q, g)):
        raise ValueError("Los parametros deben ser enteros.")

    # 2. Validar que p sea primo
    if not isprime(p):
        raise ValueError("p debe ser un numero primo.")

    # 3. Validar que q sea primo
    if not isprime(q):
        raise ValueError("q debe ser un numero primo.")

    # 4. Validar que q divida a p - 1
    if (p - 1) % q != 0:
        raise ValueError("q debe dividir exactamente a p - 1.")

    # 5. Validar que g pertenezca al campo
    if not (1 < g < p):
        raise ValueError("g debe cumplir 1 < g < p.")

    # 6. Validar pertenencia al subgrupo
    if pow(g, q, p) != 1:
        raise ValueError("g no pertenece al subgrupo de orden q.")

    # 7. Validar que g tenga orden exactamente q
    if g == 1:
        raise ValueError("g no puede ser la identidad.")

    print("\n===================================")
    print(" VALIDACION DE PARAMETROS DH")
    print("===================================")
    print(f"Numero primo p: {p}")
    print(f"Orden del subgrupo q: {q}")
    print(f"Generador g: {g}")
    print(f"q divide a p-1: {(p - 1) % q == 0}")
    print(f"g^q mod p: {pow(g, q, p)}")
    print("Orden de g: exactamente q")
    print("RESULTADO: PARAMETROS VALIDOS")
    print("===================================\n")

    return True


def obtener_parametros_prueba() -> DHParameters:
    """Parametros educativos para las primeras pruebas."""

    return DHParameters(
        p=23,
        q=11,
        g=2
    )


if __name__ == "__main__":

    parametros = obtener_parametros_prueba()

    validar_parametros(parametros)
