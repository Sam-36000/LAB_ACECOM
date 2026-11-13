
import secrets
from dataclasses import dataclass

from parametros import DHParameters, validar_parametros


@dataclass
class Cliente:
    """Representa al participante cliente A."""

    parametros: DHParameters
    clave_privada: int | None = None

    def __post_init__(self):
        validar_parametros(self.parametros)

        if self.clave_privada is not None:
            self._validar_clave_privada(self.clave_privada)

    def _validar_clave_privada(self, clave: int):
        if type(clave) is not int:
            raise ValueError("La clave privada debe ser un entero.")

        if not 1 <= clave < self.parametros.q:
            raise ValueError("La clave privada debe estar entre 1 y q-1.")

    def generar_clave_privada(self) -> int:
        """Genera un exponente privado aleatorio."""

        self.clave_privada = secrets.randbelow(
            self.parametros.q - 1
        ) + 1

        return self.clave_privada

    def obtener_clave_publica(self) -> int:
        """Calcula A = g^a mod p."""

        if self.clave_privada is None:
            raise ValueError("Primero debe generar la clave privada.")

        p = self.parametros.p
        g = self.parametros.g

        return pow(g, self.clave_privada, p)

    def calcular_secreto_compartido(
        self, clave_publica_servidor: int
    ) -> int:
        """Calcula S = B^a mod p."""

        if self.clave_privada is None:
            raise ValueError("No existe una clave privada.")

        p = self.parametros.p
        q = self.parametros.q

        if type(clave_publica_servidor) is not int:
            raise ValueError("La clave publica recibida debe ser entera.")

        if not 1 < clave_publica_servidor < p:
            raise ValueError("Clave publica fuera del campo.")

        if pow(clave_publica_servidor, q, p) != 1:
            raise ValueError("La clave publica no pertenece al subgrupo.")

        return pow(
            clave_publica_servidor,
            self.clave_privada,
            p
        )
