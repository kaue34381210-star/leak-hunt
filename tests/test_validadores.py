import pytest

from leak_hunt.validadores import validar_cnpj, validar_cpf


@pytest.mark.parametrize(
    "cpf",
    [
        "529.982." + "247-25",
        "123456789" + "09",
    ],
)
def test_aceita_cpf_com_digitos_validos(cpf: str) -> None:
    assert validar_cpf(cpf)


@pytest.mark.parametrize(
    "cpf",
    [
        "529.982." + "247-26",
        "111.111." + "111-11",
        "123",
        "cpf: " + "529.982.247-25",
    ],
)
def test_rejeita_cpf_invalido(cpf: str) -> None:
    assert not validar_cpf(cpf)


@pytest.mark.parametrize(
    "cnpj",
    [
        "11.222." + "333/0001-81",
        "112223330001" + "81",
    ],
)
def test_aceita_cnpj_com_digitos_validos(cnpj: str) -> None:
    assert validar_cnpj(cnpj)


@pytest.mark.parametrize(
    "cnpj",
    [
        "11.222." + "333/0001-82",
        "00.000." + "000/0000-00",
        "123",
        "cnpj: " + "11.222.333/0001-81",
    ],
)
def test_rejeita_cnpj_invalido(cnpj: str) -> None:
    assert not validar_cnpj(cnpj)
