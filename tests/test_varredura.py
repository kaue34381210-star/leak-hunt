import subprocess

import pytest

from leak_hunt.varredura import (
    ErroRepositorio,
    iterar_linhas_adicionadas,
    validar_repositorio,
)


def _git(repositorio, *argumentos: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repositorio), *argumentos],
        check=True,
        capture_output=True,
        text=True,
    )


def _preparar_repositorio(repositorio) -> None:
    subprocess.run(["git", "init", "-q", str(repositorio)], check=True)
    _git(repositorio, "config", "user.name", "Pessoa de Teste")
    _git(repositorio, "config", "user.email", "teste@example.invalid")


def _commit(repositorio, mensagem: str) -> None:
    _git(repositorio, "add", ".")
    _git(repositorio, "commit", "-q", "-m", mensagem)


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


def test_percorre_somente_linhas_adicionadas_em_todo_historico(tmp_path) -> None:
    _preparar_repositorio(tmp_path)
    arquivo = tmp_path / "dados.txt"
    arquivo.write_text("linha inicial\nlinha removida\n", encoding="utf-8")
    _commit(tmp_path, "commit inicial")

    arquivo.write_text("linha inicial\nlinha nova\n", encoding="utf-8")
    _commit(tmp_path, "altera arquivo")

    linhas = list(iterar_linhas_adicionadas(tmp_path))
    conteudos = [linha.conteudo for linha in linhas]

    assert conteudos.count("linha inicial") == 1
    assert conteudos.count("linha removida") == 1
    assert conteudos.count("linha nova") == 1

    linha_nova = next(linha for linha in linhas if linha.conteudo == "linha nova")
    assert linha_nova.arquivo == "dados.txt"
    assert linha_nova.numero == 2
    assert linha_nova.autor == "Pessoa de Teste"
    assert len(linha_nova.commit) == 40
    assert "T" in linha_nova.data


def test_preserva_sinais_de_mais_do_conteudo(tmp_path) -> None:
    _preparar_repositorio(tmp_path)
    (tmp_path / "codigo.txt").write_text("++ valor\n", encoding="utf-8")
    _commit(tmp_path, "adiciona sinais")

    linhas = list(iterar_linhas_adicionadas(tmp_path))

    assert [linha.conteudo for linha in linhas] == ["++ valor"]
