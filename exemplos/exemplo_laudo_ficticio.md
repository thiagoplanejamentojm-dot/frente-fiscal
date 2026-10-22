# Laudo técnico F4: EXEMPLO-FICTICIO

> Este laudo registra **observações**, não conclusões. O veredito é do Comitê de Método, depois da revisão cega e do Red Team (protocolo v2.0, seções 8 e 12 a 14).

## Identificação

| Campo | Valor |
|---|---|
| Arquivo analisado | `editado.pdf` |
| Tamanho (bytes) | `1345` |
| SHA-256 | `383bde0f00ae0f916b8610b0b31e4a478608f8c5ba5d38f70c893af64ce0c46d` |
| SHA-512 | `ef899c42de039e54f480aa5fc5dba6702bb1e3d44b4b40e0f8f4c0986a0c9b28a65c9b81280e40df2355960e7dd17220ea10c25d43508bbe370d9cab9f1bb2bc` |
| SHA-256 da custódia | `383bde0f00ae0f916b8610b0b31e4a478608f8c5ba5d38f70c893af64ce0c46d` |
| Referência (6.2) | `referencia.pdf` |
| SHA-256 da referência | `2f288fcd1de41c7ff1e6eb7a80e949685854b745d6b13b1d11112e0a06e9db83` |
| Executor | `M01` |
| Data da execução (UTC) | `2026-10-22 19:12:34` |
| Script | `laudo_f4.py v1.2` |
| SHA-256 do script | `a90bff55997af55e69321c25373bf722520b838348ca851a75357e0bd83938e7` |
| Python | `3.9.6` |

**Ferramentas externas:** exiftool: 13.55; qpdf: qpdf version 12.4.2; pdffonts: pdffonts version 26.10.0; pdfimages: pdfimages version 26.10.0; pdfinfo: pdfinfo version 26.10.0; pdftotext: pdftotext version 26.10.0

## Resumo

| Resultado | Quantidade |
|---|---|
| Conforme | 14 |
| Observação | 6 |
| Não aplicável | 1 |

| ID | Fase | Teste | Resultado |
|---|---|---|---|
| EXEMPLO-FICTICIO-T01 | F4.3 Estrutural | Hash da cópia × custódia | **Conforme** |
| EXEMPLO-FICTICIO-T02 | F4.3 Estrutural | Cabeçalho PDF | **Conforme** |
| EXEMPLO-FICTICIO-T03 | F4.3 Estrutural | Atualizações incrementais | **Observação** |
| EXEMPLO-FICTICIO-T04 | F4.3 Estrutural | Produtor e criador | **Observação** |
| EXEMPLO-FICTICIO-T05 | F4.3 Estrutural | Datas de criação e modificação | **Observação** |
| EXEMPLO-FICTICIO-T06 | F4.3 Estrutural | Fontes | **Conforme** |
| EXEMPLO-FICTICIO-T07 | F4.3 Estrutural | Páginas e imagens | **Conforme** |
| EXEMPLO-FICTICIO-T08 | F4.1 Criptográfica | Assinatura digital | **Não aplicável** |
| EXEMPLO-FICTICIO-T09 | F4.3 Estrutural | Elementos ativos | **Conforme** |
| EXEMPLO-FICTICIO-T10 | F4.3 Estrutural | Metadados (exiftool) | **Conforme** |
| EXEMPLO-FICTICIO-T11 | F4.3 Estrutural | Integridade estrutural (qpdf --check) | **Conforme** |
| EXEMPLO-FICTICIO-T12 | F4.3 Estrutural | Fontes (pdffonts) | **Conforme** |
| EXEMPLO-FICTICIO-T13 | F4.3 Estrutural | Imagens (pdfimages -list) | **Conforme** |
| EXEMPLO-FICTICIO-T14 | F4.3 Estrutural | Camada de texto por página | **Conforme** |
| EXEMPLO-FICTICIO-T15 | F4.3 Estrutural | Texto das revisões × versão final | **Observação** |
| EXEMPLO-FICTICIO-T16 | F4.2 Referência | Versão do PDF × referência | **Conforme** |
| EXEMPLO-FICTICIO-T17 | F4.2 Referência | Produtor × referência | **Observação** |
| EXEMPLO-FICTICIO-T18 | F4.2 Referência | Criador × referência | **Conforme** |
| EXEMPLO-FICTICIO-T19 | F4.2 Referência | Tamanho de página × referência | **Conforme** |
| EXEMPLO-FICTICIO-T20 | F4.2 Referência | Número de revisões × referência | **Observação** |
| EXEMPLO-FICTICIO-T21 | F4.2 Referência | Fontes × referência | **Conforme** |

## Detalhes

### EXEMPLO-FICTICIO-T01: Hash da cópia × custódia

- **Fase:** F4.3 Estrutural
- **Comando:** `sha256`
- **Resultado:** Conforme
- **Observação:** SHA-256 da cópia igual ao da custódia.

### EXEMPLO-FICTICIO-T02: Cabeçalho PDF

- **Fase:** F4.3 Estrutural
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Conforme
- **Observação:** Cabeçalho %PDF-1.4.

### EXEMPLO-FICTICIO-T03: Atualizações incrementais

- **Fase:** F4.3 Estrutural
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Observação
- **Observação:** 1 atualização(ões) incremental(is) depois da geração. Cada versão anterior foi salva em revisoes/. Pelo menos uma atualização ACRESCENTA OU SUBSTITUI CONTEÚDO DE PÁGINA COM TEXTO OU IMAGEM: candidato a indício pela regra G3, exige comparação visual das revisões e revisão cega. Revisão 2: 480 bytes; objetos substituídos [4, 6]; novos -; tipos {'Conteúdo de página (com texto)': 1, 'Info (metadados)': 1}; texto desenhado (aproximado): ['DECLARACAO FICTICIA DE TESTE', 'Rendimentos tributaveis: 150.000,00']
- **Explicação alternativa a considerar:** Assinar, preencher formulário, anotar ou salvar num leitor de PDF cria revisões sem mudar o conteúdo original; comparar visualmente revisao_N.pdf com a final.
- **Saída bruta:** `brutos/revisoes.json`

### EXEMPLO-FICTICIO-T04: Produtor e criador

- **Fase:** F4.3 Estrutural
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Observação
- **Observação:** Mais de um produtor/criador no arquivo: ele passou por mais de um programa. Producer (Info): ['Adobe Acrobat Pro 2024', 'Programa IRPF 2025 (ficticio)']; Creator (Info): ['IRPF']; Producer (XMP): -; CreatorTool (XMP): -
- **Explicação alternativa a considerar:** Reexportação ou assinatura por outro software (regra G2); comparar com as revisões.

### EXEMPLO-FICTICIO-T05: Datas de criação e modificação

- **Fase:** F4.3 Estrutural
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Observação
- **Observação:** Modificação 533 dia(s) e 11 hora(s) depois da criação. CreationDate: ["D:20250430101500-03'00'"]; ModDate: ["D:20250430101500-03'00'", "D:20261015220000-03'00'"]; XMP CreateDate: -; XMP ModifyDate: -
- **Explicação alternativa a considerar:** Assinatura, reexportação ou salvar novamente atualizam a data de modificação; datas sem fuso foram comparadas como UTC.

### EXEMPLO-FICTICIO-T06: Fontes

- **Fase:** F4.3 Estrutural
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Conforme
- **Observação:** Fontes embutidas ou referenciadas: Helvetica. Comparar com a referência (6.2) e checar homogeneidade.

### EXEMPLO-FICTICIO-T07: Páginas e imagens

- **Fase:** F4.3 Estrutural
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Conforme
- **Observação:** 1 página(s); 0 imagem(ns); MediaBox 0 0 595 842.

### EXEMPLO-FICTICIO-T08: Assinatura digital

- **Fase:** F4.1 Criptográfica
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Não aplicável
- **Observação:** Nenhuma assinatura digital (/ByteRange) no arquivo: a verificação criptográfica não se aplica.

### EXEMPLO-FICTICIO-T09: Elementos ativos

- **Fase:** F4.3 Estrutural
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes)`
- **Resultado:** Conforme
- **Observação:** Sem JavaScript, ações automáticas, anexos ou envio de formulário.

### EXEMPLO-FICTICIO-T10: Metadados (exiftool)

- **Fase:** F4.3 Estrutural
- **Comando:** `exiftool -a -G1 -s /private/tmp/claude-501/-Users-thiagohenriquedossantos-Library-Application-Support-Claude-scratch-workspaces-804cc44d-4dbe-47c5-903d-e6696d8659ef-472c2db6-3859-4891-93cc-d758a6e2290a-scratch-2026-10-22-286ae6/762ce073-14c1-4461-86fe-e53570fcc397/scratchpad/pdfs/editado.pdf`
- **Resultado:** Conforme
- **Observação:** Saída registrada para revisão e comparação com a referência.
- **Saída bruta:** `brutos/exiftool.txt`

### EXEMPLO-FICTICIO-T11: Integridade estrutural (qpdf --check)

- **Fase:** F4.3 Estrutural
- **Comando:** `qpdf --check /private/tmp/claude-501/-Users-thiagohenriquedossantos-Library-Application-Support-Claude-scratch-workspaces-804cc44d-4dbe-47c5-903d-e6696d8659ef-472c2db6-3859-4891-93cc-d758a6e2290a-scratch-2026-10-22-286ae6/762ce073-14c1-4461-86fe-e53570fcc397/scratchpad/pdfs/editado.pdf`
- **Resultado:** Conforme
- **Observação:** Sem erros de sintaxe ou codificação.
- **Saída bruta:** `brutos/qpdf.txt`

### EXEMPLO-FICTICIO-T12: Fontes (pdffonts)

- **Fase:** F4.3 Estrutural
- **Comando:** `pdffonts /private/tmp/claude-501/-Users-thiagohenriquedossantos-Library-Application-Support-Claude-scratch-workspaces-804cc44d-4dbe-47c5-903d-e6696d8659ef-472c2db6-3859-4891-93cc-d758a6e2290a-scratch-2026-10-22-286ae6/762ce073-14c1-4461-86fe-e53570fcc397/scratchpad/pdfs/editado.pdf`
- **Resultado:** Conforme
- **Observação:** Saída registrada para revisão e comparação com a referência.
- **Saída bruta:** `brutos/pdffonts.txt`

### EXEMPLO-FICTICIO-T13: Imagens (pdfimages -list)

- **Fase:** F4.3 Estrutural
- **Comando:** `pdfimages -list /private/tmp/claude-501/-Users-thiagohenriquedossantos-Library-Application-Support-Claude-scratch-workspaces-804cc44d-4dbe-47c5-903d-e6696d8659ef-472c2db6-3859-4891-93cc-d758a6e2290a-scratch-2026-10-22-286ae6/762ce073-14c1-4461-86fe-e53570fcc397/scratchpad/pdfs/editado.pdf`
- **Resultado:** Conforme
- **Observação:** Saída registrada para revisão e comparação com a referência.
- **Saída bruta:** `brutos/pdfimages.txt`

### EXEMPLO-FICTICIO-T14: Camada de texto por página

- **Fase:** F4.3 Estrutural
- **Comando:** `pdfinfo + pdftotext -layout`
- **Resultado:** Conforme
- **Observação:** Todas as páginas têm camada de texto.
- **Saída bruta:** `brutos/texto_paginas.txt`

### EXEMPLO-FICTICIO-T15: Texto das revisões × versão final

- **Fase:** F4.3 Estrutural
- **Comando:** `pdftotext -layout revisoes/revisao_N.pdf`
- **Resultado:** Observação
- **Observação:** Texto extraído difere da versão final nas revisões [1]: candidato a indício (regra G3). revisão 1 → final: saiu ['Rendimentos tributaveis: 100.000,00']; entrou ['Rendimentos tributaveis: 150.000,00']
- **Explicação alternativa a considerar:** Diferenças de extração podem vir de anotações ou campos de formulário.
- **Saída bruta:** `brutos/texto_revisoes_diff.txt`

### EXEMPLO-FICTICIO-T16: Versão do PDF × referência

- **Fase:** F4.2 Referência
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes) --referencia`
- **Resultado:** Conforme
- **Observação:** Analisado: 1.4; referência: 1.4.

### EXEMPLO-FICTICIO-T17: Produtor × referência

- **Fase:** F4.2 Referência
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes) --referencia`
- **Resultado:** Observação
- **Observação:** Analisado: ['Adobe Acrobat Pro 2024', 'Programa IRPF 2025 (ficticio)']; referência: ['Programa IRPF 2025 (ficticio)'].
- **Explicação alternativa a considerar:** Versão diferente do programa, reexportação ou impressão por outro caminho (regra G2).

### EXEMPLO-FICTICIO-T18: Criador × referência

- **Fase:** F4.2 Referência
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes) --referencia`
- **Resultado:** Conforme
- **Observação:** Analisado: ['IRPF']; referência: ['IRPF'].

### EXEMPLO-FICTICIO-T19: Tamanho de página × referência

- **Fase:** F4.2 Referência
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes) --referencia`
- **Resultado:** Conforme
- **Observação:** Analisado: 0 0 595 842; referência: 0 0 595 842.

### EXEMPLO-FICTICIO-T20: Número de revisões × referência

- **Fase:** F4.2 Referência
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes) --referencia`
- **Resultado:** Observação
- **Observação:** Analisado: 2; referência: 1.
- **Explicação alternativa a considerar:** Assinatura ou salvamento posterior.

### EXEMPLO-FICTICIO-T21: Fontes × referência

- **Fase:** F4.2 Referência
- **Comando:** `laudo_f4.py v1.2 (Python, leitura de bytes) --referencia`
- **Resultado:** Conforme
- **Observação:** Fontes só no analisado: -; só na referência: -; em comum: ['Helvetica'].

## Como reproduzir

1. Baixe o arquivo pela URL registrada na custódia e confira o SHA-256 acima.
2. Confira o SHA-256 do script acima.
3. Rode: `python3 laudo_f4.py ARQUIVO.pdf --id EXEMPLO-FICTICIO --executor SEU_CODINOME --hash-esperado 383bde0f00ae0f916b8610b0b31e4a478608f8c5ba5d38f70c893af64ce0c46d` --referencia REFERENCIA.pdf
4. Os resultados devem coincidir; diferenças só são esperadas nos testes de ferramentas externas que não estejam instaladas.
