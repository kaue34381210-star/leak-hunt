# leak-hunt

Scanner de segredos em histórico Git, com regras focadas no contexto brasileiro.

Vai além do padrão internacional (AWS/GCP/Slack tokens) e detecta o que costuma passar batido em code review no Brasil: chaves PIX, tokens Serpro, certificados e-CNPJ, strings de conexão de contabilidade, dados sensíveis LGPD (CPF/CNPJ hardcoded, CEP em log).

Roda 100% local — nenhum segredo sai da sua máquina.

## Status

Em desenvolvimento inicial. Não usar em produção ainda.

## Instalação para desenvolvimento

```bash
pipx install -e /home/usuario/leak-hunt
```

## Uso atual

```bash
leak-hunt --version
python -m leak_hunt --version
leak-hunt /caminho/do/repo
leak-hunt --since 2024-01-01 /caminho/do/repo
```

## Uso planejado

```bash
leak-hunt --format json . > relatorio.json
```

## Licença

MIT — ver [LICENSE](LICENSE).
