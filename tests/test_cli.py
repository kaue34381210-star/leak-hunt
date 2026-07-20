import subprocess

import pytest

from leak_hunt.cli import main


def test_exibe_versao(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as erro:
        main(["--version"])

    assert erro.value.code == 0
    assert capsys.readouterr().out == "leak-hunt 0.0.1\n"


def test_exibe_ajuda_sem_argumentos(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0

    saida = capsys.readouterr().out
    assert "usage: leak-hunt" in saida
    assert "--version" in saida
    assert "CAMINHO" in saida


def test_recebe_caminho_do_repositorio(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    assert main([str(tmp_path)]) == 0

    assert capsys.readouterr().out == f"Repositório Git válido: {tmp_path}\n"


def test_rejeita_diretorio_sem_repositorio(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([str(tmp_path)]) == 2

    captura = capsys.readouterr()
    assert captura.out == ""
    assert "não é um repositório Git" in captura.err
