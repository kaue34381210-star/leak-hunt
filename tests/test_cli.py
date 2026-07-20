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
