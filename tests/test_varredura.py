import subprocess

import pytest

from leak_hunt.varredura import ErroRepositorio, validar_repositorio


def test_valida_repositorio_git(tmp_path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    assert validar_repositorio(tmp_path) == tmp_path.resolve()


def test_rejeita_caminho_inexistente(tmp_path) -> None:
    caminho = tmp_path / "inexistente"

    with pytest.raises(ErroRepositorio, match="o caminho não existe"):
        validar_repositorio(caminho)


def test_rejeita_arquivo_comum(tmp_path) -> None:
    caminho = tmp_path / "arquivo.txt"
    caminho.write_text("conteúdo", encoding="utf-8")

    with pytest.raises(ErroRepositorio, match="não é um diretório"):
        validar_repositorio(caminho)
