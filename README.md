# leak-hunt

[![CI](https://github.com/kaue34381210-star/leak-hunt/actions/workflows/ci.yml/badge.svg)](https://github.com/kaue34381210-star/leak-hunt/actions/workflows/ci.yml)

Scanner de segredos em histórico Git, com regras focadas no contexto brasileiro.
O MVP combina formatos genéricos selecionados com chaves PIX e validação por
dígito verificador de CPF/CNPJ.

Roda 100% local — nenhum segredo sai da sua máquina.

## Status

Versão `0.1.0` preparada. Ainda não publicada no PyPI.

O workflow `.github/workflows/release.yml` publica tags `v*` pelo Trusted
Publishing do PyPI, sem token persistente. Antes da primeira tag, é necessário
registrar o publisher para o repositório `kaue34381210-star/leak-hunt`, workflow
`release.yml` e environment `pypi`, configurando aprovação manual nesse
environment. A tag precisa coincidir com a versão do pacote, por exemplo
`v0.1.0`.

## Instalação para desenvolvimento

```bash
pipx install -e .
```

Depois da publicação no PyPI, a instalação será:

```bash
pipx install leak-hunt
```

## Uso atual

```bash
leak-hunt --version
python -m leak_hunt --version
leak-hunt /caminho/do/repo
leak-hunt --since 2024-01-01 /caminho/do/repo
leak-hunt --format json /caminho/do/repo > relatorio.json
leak-hunt --format sarif /caminho/do/repo > relatorio.sarif
leak-hunt --exclude 'tests/**' --exclude '**/fixtures/**' /caminho/do/repo
leak-hunt --only pix-email --skip cpf-hardcoded /caminho/do/repo
leak-hunt --refs head /caminho/do/repo
leak-hunt --fail-on critico,alto /caminho/do/repo
leak-hunt --staged /caminho/do/repo
leak-hunt --update-baseline /caminho/do/repo
```

O relatório nunca mostra o valor completo encontrado. O formato JSON usa a
versão de schema `1` e pode ser consumido por ferramentas de CI.
Ocorrências repetidas do mesmo segredo são agrupadas com a primeira aparição,
a mais recente, a quantidade de ocorrências e os arquivos afetados.
Cada achado inclui severidade `critico`, `alto`, `medio` ou `baixo`.
O formato SARIF `2.1.0` pode ser enviado ao GitHub Code Scanning; nele,
severidades crítica/alta viram `error`, média vira `warning` e baixa vira
`note`.

Exclusões também podem ser declaradas, uma por linha, em `.leakhuntignore` na
raiz analisada. Os padrões são globs, são aplicados em ordem e aceitam `!` para
reincluir um caminho. Nada é ignorado por padrão.

`--only CODE` e `--skip CODE` podem ser repetidos para ativar ou silenciar
regras específicas. Quando usados juntos, `--skip` prevalece.

Por padrão, `--refs all` cobre todas as referências. Use `--refs head` para
somente o histórico alcançável pelo `HEAD` ou `--refs branches` para branches
locais.

`--staged` analisa somente as linhas adicionadas ao index, antes do commit. O
caminho pode ser omitido nesse modo, usando o diretório atual. O repositório
também fornece o hook `leak-hunt` em `.pre-commit-hooks.yaml`, com
`pass_filenames: false`, para integração com o framework pre-commit.

## Baseline

Para aceitar os achados atuais e fazer o CI falhar apenas em achados novos:

```bash
leak-hunt --update-baseline /caminho/do/repo
git add .leakhuntbaseline.json
```

A baseline guarda somente fingerprints SHA-256 versionadas de
`regra + caminho + valor`; o valor bruto nunca é persistido. Uma mudança no
valor ou no caminho volta a produzir um achado. A atualização exige uma
varredura completa, sem `--staged`, `--since`, `--refs`, `--only`, `--skip` ou
`--exclude` fornecido pela CLI. As regras de `.leakhuntignore` continuam sendo
aplicadas.

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
- Além das linhas adicionadas em patches, a análise inspeciona blobs de até
  10 MiB com extensões `.pfx`, `.p12`, `.jks`, `.keystore` e `.key`.
  PKCS#12 e chaves DER exigem um envelope com comprimento estruturalmente
  válido; JKS exige seu magic completo. Chaves PEM continuam cobertas pela
  regra textual de cabeçalho, sem gerar um segundo achado por blob.
- Nenhuma regra consulta serviços externos para confirmar credenciais. A
  execução permanece integralmente local.
- Exemplos públicos conhecidos são ignorados somente quando o valor completo
  coincide exatamente com a allowlist embutida da respectiva regra.

## Códigos de saída

- `0`: varredura concluída sem achados bloqueantes.
- `1`: um ou mais possíveis segredos encontrados. Com `--fail-on`, somente
  achados nas severidades selecionadas causam esse código.
- `2`: caminho, argumento ou execução do Git inválidos.

## Regras do MVP

- AWS Access Key, cabeçalhos de chave privada e tokens de acesso GitHub são
  críticos; JWT é alto.
- Chaves PIX por e-mail, EVP, CPF e CNPJ em contexto PIX são médias.
- CPF e CNPJ hardcoded são médios, com dígitos válidos e no mínimo cinco
  ocorrências no mesmo arquivo.
- Valores não vazios versionados em `.env` têm severidade alta e incluem
  variantes como `.env.production`;
  arquivos de modelo (`.example`, `.sample`, `.template`, `.dist`) são ignorados.
- Contêineres PKCS#12, Java KeyStores e arquivos de chave privada detectados por
  blob têm severidade crítica.

## Licença

MIT — ver [LICENSE](LICENSE).
