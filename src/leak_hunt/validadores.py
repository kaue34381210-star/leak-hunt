"""Validadores locais para documentos brasileiros."""


_SEPARADORES_PERMITIDOS = frozenset(".-/ ")


def _normalizar_documento(valor: str) -> str | None:
    if any(
        not caractere.isdigit() and caractere not in _SEPARADORES_PERMITIDOS
        for caractere in valor
    ):
        return None
    return "".join(caractere for caractere in valor if caractere.isdigit())


def _digito_verificador(digitos: str, pesos: tuple[int, ...]) -> int:
    soma = sum(int(digito) * peso for digito, peso in zip(digitos, pesos))
    resto = soma % 11
    return 0 if resto < 2 else 11 - resto


def validar_cpf(valor: str) -> bool:
    """Confere tamanho, repetições e os dois dígitos verificadores do CPF."""
    digitos = _normalizar_documento(valor)
    if digitos is None or len(digitos) != 11 or len(set(digitos)) == 1:
        return False

    base = digitos[:9]
    primeiro = _digito_verificador(base, tuple(range(10, 1, -1)))
    segundo = _digito_verificador(
        f"{base}{primeiro}",
        tuple(range(11, 1, -1)),
    )
    return digitos[-2:] == f"{primeiro}{segundo}"


def validar_cnpj(valor: str) -> bool:
    """Confere tamanho, repetições e os dois dígitos verificadores do CNPJ."""
    digitos = _normalizar_documento(valor)
    if digitos is None or len(digitos) != 14 or len(set(digitos)) == 1:
        return False

    base = digitos[:12]
    primeiro = _digito_verificador(
        base,
        (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2),
    )
    segundo = _digito_verificador(
        f"{base}{primeiro}",
        (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2),
    )
    return digitos[-2:] == f"{primeiro}{segundo}"
