from leak_hunt.exclusoes import caminho_excluido


def test_aplica_globs_de_arquivo_e_diretorio() -> None:
    padroes = ("tests/", "**/fixtures/**", "*.example")

    assert caminho_excluido("tests/test_cli.py", padroes)
    assert caminho_excluido("app/fixtures/segredo.txt", padroes)
    assert caminho_excluido("config.env.example", padroes)
    assert not caminho_excluido("src/app.py", padroes)


def test_permite_reinclusao_em_ordem() -> None:
    padroes = ("tests/", "!tests/test_seguranca.py")

    assert caminho_excluido("tests/test_comum.py", padroes)
    assert not caminho_excluido("tests/test_seguranca.py", padroes)
