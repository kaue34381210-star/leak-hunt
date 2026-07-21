# Changelog

## 0.1.0 — 2026-07-20

Primeiro MVP funcional.

### Adicionado

- Varredura em streaming de linhas adicionadas em todo o histórico Git.
- Relatórios de texto e JSON com valores ofuscados e códigos de saída para CI.
- Regras para AWS Access Key, chave privada, JWT e tokens de acesso GitHub.
- Regras PIX por e-mail, EVP, CPF e CNPJ, com validação de documentos.
- Detecção de valores versionados em arquivos `.env` reais.
- Exclusões por glob, `.leakhuntignore`, seleção de regras e escopo de refs.
- Deduplicação com contagem de ocorrências e arquivos afetados.
- Allowlist exata para exemplos públicos conhecidos da AWS e do jwt.io.
- Severidade por regra e política de saída configurável com `--fail-on`.
- Varredura preventiva do index com `--staged` e hook para pre-commit.
- Baseline versionada para suprimir achados conhecidos sem persistir valores.
- Teste ponta a ponta da CLI contra um histórico Git temporário real.
- Release por tag para o PyPI via Trusted Publishing, sem token persistente.
- Relatório SARIF 2.1.0 compatível com GitHub Code Scanning.
- Detecção por conteúdo de PKCS#12, JKS e arquivos de chave privada em blobs.
- Suporte a Python 3.10–3.13 com cobertura mínima automatizada de 85%.
