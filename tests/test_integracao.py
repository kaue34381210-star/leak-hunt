import json
import os
from pathlib import Path
import subprocess
import sys


RAIZ_PROJETO = Path(__file__).resolve().parents[1]


def _git(repositorio: Path, *argumentos: str) -> str:
    resultado = subprocess.run(
        ["git", "-C", str(repositorio), *argumentos],
        check=True,
        capture_output=True,
        text=True,
    )
    return resultado.stdout.strip()


def _executar_cli(*argumentos: str) -> subprocess.CompletedProcess[str]:
    ambiente = os.environ | {
        "PYTHONPATH": str(RAIZ_PROJETO / "src"),
    }
    return subprocess.run(
        [sys.executable, "-m", "leak_hunt", *argumentos],
        cwd=RAIZ_PROJETO,
        env=ambiente,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_varre_historico_git_de_ponta_a_ponta(tmp_path) -> None:
    segredo = "AKIA" + "E2ETEST" + "0" * 9
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    _git(tmp_path, "config", "user.name", "Pessoa de Teste")
    _git(tmp_path, "config", "user.email", "teste@example.invalid")

    (tmp_path / "README.md").write_text("projeto seguro\n", encoding="utf-8")
    _git(tmp_path, "add", "README.md")
    _git(tmp_path, "commit", "-q", "-m", "conteúdo seguro")

    (tmp_path / "config.py").write_text(
        f'CHAVE = "{segredo}"\n',
        encoding="utf-8",
    )
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-q", "-m", "adiciona configuração")
    commit_esperado = _git(tmp_path, "rev-parse", "HEAD")

    resultado = _executar_cli("--format", "json", "--refs", "head", str(tmp_path))

    assert resultado.returncode == 1
    assert resultado.stderr == ""
    assert segredo not in resultado.stdout
    documento = json.loads(resultado.stdout)
    assert documento["resumo"]["total_achados"] == 1
    assert documento["achados"][0]["codigo"] == "aws-access-key"
    assert documento["achados"][0]["severidade"] == "critico"
    assert documento["achados"][0]["arquivo"] == "config.py"
    assert documento["achados"][0]["linha"] == 1
    assert documento["achados"][0]["commit"] == commit_esperado

    sem_config = _executar_cli("--exclude", "config.py", str(tmp_path))
    assert sem_config.returncode == 0
    assert "Nenhum segredo encontrado" in sem_config.stdout
