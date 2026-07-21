import pytest

from leak_hunt.regras import detectar


def _codigos(texto: str) -> list[str]:
    return [deteccao.codigo for deteccao in detectar(texto)]


def test_regras_brasileiras_tem_severidade_media() -> None:
    deteccao = next(detectar('pix = "financeiro@example.com"'))

    assert deteccao.severidade == "medio"


@pytest.mark.parametrize(
    ("texto", "codigo"),
    [
        ('chave_pix = "financeiro@empresa.invalid"', "pix-email"),
        (
            'pix_evp = "' + "123e4567-e89b-42d3" + "-a456-426614174000" + '"',
            "pix-evp",
        ),
        ('pix_cpf = "' + "529.982." + "247-25" + '"', "pix-cpf"),
        ('dict_cnpj = "' + "11.222." + "333/0001-81" + '"', "pix-cnpj"),
    ],
)
def test_detecta_chaves_pix_em_contexto(texto: str, codigo: str) -> None:
    assert codigo in _codigos(texto)


@pytest.mark.parametrize(
    "texto",
    [
        'contato = "financeiro@empresa.invalid"',
        'id = "' + "123e4567-e89b-42d3" + "-a456-426614174000" + '"',
        'pix_cpf = "' + "529.982." + "247-26" + '"',
        'pix_cnpj = "' + "11.222." + "333/0001-82" + '"',
    ],
)
def test_ignora_chaves_pix_sem_contexto_ou_invalidas(texto: str) -> None:
    assert not any(codigo.startswith("pix-") for codigo in _codigos(texto))


def test_documento_hardcoded_exige_cinco_ocorrencias_no_arquivo() -> None:
    cpf = "529.982." + "247-25"

    deteccao = next(
        item for item in detectar(f'cliente = "{cpf}"')
        if item.codigo == "cpf-hardcoded"
    )

    assert deteccao.minimo_por_arquivo == 5
