import json
import subprocess

import pytest

from leak_hunt.cli import main


def test_exibe_versao(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as erro:
        main(["--version"])

    assert erro.value.code == 0
    assert capsys.readouterr().out == "leak-hunt 0.1.0\n"


def test_exibe_ajuda_sem_argumentos(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0

    saida = capsys.readouterr().out
    assert "usage: leak-hunt" in saida
    assert "--version" in saida
    assert "--since" in saida
    assert "--format" in saida
    assert "--refs" in saida
    assert "--staged" in saida
    assert "--exclude" in saida
    assert "--only" in saida
    assert "--skip" in saida
    assert "--fail-on" in saida
    assert "--update-baseline" in saida
    assert "CAMINHO" in saida


def test_rejeita_data_since_fora_do_formato_iso(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as erro:
        main(["--since", "ontem", "."])

    assert erro.value.code == 2
    assert "AAAA-MM-DD" in capsys.readouterr().err


def test_rejeita_codigo_de_regra_desconhecido(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--only", "inexistente", "."]) == 2

    assert "código de regra desconhecido" in capsys.readouterr().err


def test_rejeita_severidade_desconhecida(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as erro:
        main(["--fail-on", "urgente", "."])

    assert erro.value.code == 2
    assert "severidade inválida" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argumentos",
    [
        ["--staged", "--since", "2026-01-01", "."],
        ["--staged", "--refs", "head", "."],
    ],
)
def test_rejeita_filtros_de_historico_com_staged(
    argumentos: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as erro:
        main(argumentos)

    assert erro.value.code == 2
    assert "--staged não pode ser combinado" in capsys.readouterr().err


def test_recebe_caminho_do_repositorio(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    assert main([str(tmp_path)]) == 0

    assert capsys.readouterr().out == (
        "Nenhum segredo encontrado.\n"
        "Linhas adicionadas analisadas: 0\n"
    )


def test_rejeita_diretorio_sem_repositorio(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([str(tmp_path)]) == 2

    captura = capsys.readouterr()
    assert captura.out == ""
    assert "não é um repositório Git" in captura.err


def test_emite_json_valido_para_repositorio_sem_achados(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)

    assert main(["--format", "json", str(tmp_path)]) == 0

    documento = json.loads(capsys.readouterr().out)
    assert documento["versao_schema"] == 1
    assert documento["repositorio"] == str(tmp_path)
    assert documento["resumo"]["total_achados"] == 0
    assert documento["achados"] == []


def test_retorna_um_e_ofusca_quando_encontra_segredo(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    segredo = "AKIA" + "FAKE" + "0" * 12
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Teste"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "config",
            "user.email",
            "teste@example.invalid",
        ],
        check=True,
    )
    (tmp_path / "config.py").write_text(
        f'CHAVE = "{segredo}"\n',
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "config.py"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "teste"],
        check=True,
    )

    assert main([str(tmp_path)]) == 1

    saida = capsys.readouterr().out
    assert "AWS Access Key" in saida
    assert "Severidade: critico" in saida
    assert "config.py:1" in saida
    assert segredo not in saida
    assert "AKIA…0000" in saida

    assert main(["--fail-on", "alto,medio", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["--fail-on", "critico,alto", str(tmp_path)]) == 1


def test_staged_detecta_index_sem_caminho_explicito(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    segredo = "AKIA" + "STAGED" + "0" * 10
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "config.py").write_text(
        f'CHAVE = "{segredo}"\n',
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", "config.py"],
        check=True,
    )
    monkeypatch.chdir(tmp_path)

    assert main(["--staged"]) == 1

    saida = capsys.readouterr().out
    assert "AWS Access Key" in saida
    assert "Commit: INDEX" in saida
    assert segredo not in saida


def test_atualiza_baseline_e_suprime_achado_existente(
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    segredo = "AKIA" + "BASE" + "0" * 12
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Teste"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "config",
            "user.email",
            "teste@example.invalid",
        ],
        check=True,
    )
    (tmp_path / "config.py").write_text(segredo + "\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "segredo"],
        check=True,
    )

    assert main(["--update-baseline", str(tmp_path)]) == 0
    captura = capsys.readouterr()
    baseline = (tmp_path / ".leakhuntbaseline.json").read_text(encoding="utf-8")
    assert "Baseline atualizada" in captura.err
    assert segredo not in baseline

    assert main([str(tmp_path)]) == 0
    assert "Nenhum segredo encontrado" in capsys.readouterr().out
