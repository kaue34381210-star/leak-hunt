# leak-hunt

Scanner de segredos em histórico Git, com regras focadas no contexto brasileiro.

Vai além do padrão internacional (AWS/GCP/Slack tokens) e detecta o que costuma passar batido em code review no Brasil: chaves PIX, tokens Serpro, certificados e-CNPJ, strings de conexão de contabilidade, dados sensíveis LGPD (CPF/CNPJ hardcoded, CEP em log).

Roda 100% local — nenhum segredo sai da sua máquina.

## Status

MVP funcional em desenvolvimento. Ainda não publicado no PyPI.

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
leak-hunt --format json /caminho/do/repo > relatorio.json
```

O relatório nunca mostra o valor completo encontrado. O formato JSON usa a
versão de schema `1` e pode ser consumido por ferramentas de CI.

## Códigos de saída

- `0`: varredura concluída sem achados.
- `1`: um ou mais possíveis segredos encontrados.
- `2`: caminho, argumento ou execução do Git inválidos.

## Regras do MVP

- AWS Access Key, cabeçalhos de chave privada e JWT.
- Chaves PIX por e-mail, EVP, CPF e CNPJ em contexto PIX.
- CPF e CNPJ hardcoded, com dígitos válidos e no mínimo cinco ocorrências no
  mesmo arquivo.

## Licença

MIT — ver [LICENSE](LICENSE).
