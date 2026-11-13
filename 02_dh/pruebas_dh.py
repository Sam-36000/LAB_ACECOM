
import pytest

from parametros import (
    obtener_parametros_prueba,
    validar_parametros
)

from cliente import Cliente
from servidor import Servidor


def test_parametros_validos():
    """Comprueba los parametros del grupo."""

    parametros = obtener_parametros_prueba()

    assert validar_parametros(parametros) is True


def test_clave_publica_cliente():
    """Comprueba A = g^a mod p."""

    parametros = obtener_parametros_prueba()

    cliente = Cliente(parametros, clave_privada=3)

    assert cliente.obtener_clave_publica() == 8


def test_clave_publica_servidor():
    """Comprueba B = g^b mod p."""

    parametros = obtener_parametros_prueba()

    servidor = Servidor(parametros, clave_privada=7)

    assert servidor.obtener_clave_publica() == 13


def test_secreto_compartido():
    """Comprueba que ambos extremos obtienen S = 12."""

    parametros = obtener_parametros_prueba()

    cliente = Cliente(parametros, clave_privada=3)
    servidor = Servidor(parametros, clave_privada=7)

    A = cliente.obtener_clave_publica()
    B = servidor.obtener_clave_publica()

    secreto_cliente = cliente.calcular_secreto_compartido(B)
    secreto_servidor = servidor.calcular_secreto_compartido(A)

    assert secreto_cliente == secreto_servidor
    assert secreto_cliente == 12


def test_generacion_aleatoria():
    """Comprueba la generacion de exponentes privados."""

    parametros = obtener_parametros_prueba()

    cliente = Cliente(parametros)
    servidor = Servidor(parametros)

    a = cliente.generar_clave_privada()
    b = servidor.generar_clave_privada()

    assert 1 <= a < parametros.q
    assert 1 <= b < parametros.q


def test_rechazar_clave_privada_invalida():

    parametros = obtener_parametros_prueba()

    with pytest.raises(ValueError):
        Cliente(parametros, clave_privada=11)

    with pytest.raises(ValueError):
        Servidor(parametros, clave_privada=0)


def test_rechazar_clave_publica_invalida():

    parametros = obtener_parametros_prueba()

    cliente = Cliente(parametros, clave_privada=3)

    with pytest.raises(ValueError):
        cliente.calcular_secreto_compartido(1)


def test_rechazar_clave_publica_fuera_del_subgrupo():

    parametros = obtener_parametros_prueba()

    cliente = Cliente(parametros, clave_privada=3)

    with pytest.raises(ValueError):
        cliente.calcular_secreto_compartido(5)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
