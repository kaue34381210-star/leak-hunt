# leak-hunt

[![CI](https://github.com/kaue34381210-star/leak-hunt/actions/workflows/ci.yml/badge.svg)](https://github.com/kaue34381210-star/leak-hunt/actions/workflows/ci.yml)

Scanner de segredos em histórico Git, com regras focadas no contexto brasileiro.
O MVP combina formatos genéricos selecionados com chaves PIX e validação por
dígito verificador de CPF/CNPJ.

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
leak-hunt --exclude 'tests/**' --exclude '**/fixtures/**' /caminho/do/repo
leak-hunt --only pix-email --skip cpf-hardcoded /caminho/do/repo
leak-hunt --refs head /caminho/do/repo
```

O relatório nunca mostra o valor completo encontrado. O formato JSON usa a
versão de schema `1` e pode ser consumido por ferramentas de CI.
Ocorrências repetidas do mesmo segredo são agrupadas com a primeira aparição,
a mais recente, a quantidade de ocorrências e os arquivos afetados.

Exclusões também podem ser declaradas, uma por linha, em `.leakhuntignore` na
raiz analisada. Os padrões são globs, são aplicados em ordem e aceitam `!` para
reincluir um caminho. Nada é ignorado por padrão.

`--only CODE` e `--skip CODE` podem ser repetidos para ativar ou silenciar
regras específicas. Quando usados juntos, `--skip` prevalece.

Por padrão, `--refs all` cobre todas as referências. Use `--refs head` para
somente o histórico alcançável pelo `HEAD` ou `--refs branches` para branches
locais.

## Escopo e limitações

- O leak-hunt é complementar a gitleaks e trufflehog. Use essas ferramentas
  quando precisar de cobertura genérica ampla; use o leak-hunt também quando
  precisar das regras brasileiras e validações locais.
- O contexto PIX é avaliado na mesma linha do valor. Um comentário em outra
  linha ou no topo do arquivo não é usado como contexto.
- O histórico textual é decodificado como UTF-8. Bytes inválidos, comuns em
  commits antigos em outras codificações, são substituídos por `�`; a
  varredura continua, mas uma regra dependente de texto acentuado pode perder
  precisão.
- A regra de chave privada considera o cabeçalho isolado um indício suficiente;
  ela não exige nem valida o corpo criptográfico.
- A análise atual cobre linhas adicionadas em patches. Arquivos binários, como
  certificados `.pfx` e `.p12`, exigirão uma futura análise de blobs.
- Nenhuma regra consulta serviços externos para confirmar credenciais. A
  execução permanece integralmente local.

## Códigos de saída

- `0`: varredura concluída sem achados.
- `1`: um ou mais possíveis segredos encontrados.
- `2`: caminho, argumento ou execução do Git inválidos.

## Regras do MVP

- AWS Access Key, cabeçalhos de chave privada, JWT e tokens de acesso GitHub.
- Chaves PIX por e-mail, EVP, CPF e CNPJ em contexto PIX.
- CPF e CNPJ hardcoded, com dígitos válidos e no mínimo cinco ocorrências no
  mesmo arquivo.
- Valores não vazios versionados em `.env` e variantes como `.env.production`;
  arquivos de modelo (`.example`, `.sample`, `.template`, `.dist`) são ignorados.

## Licença

MIT — ver [LICENSE](LICENSE).
