# Pacote da frente fiscal — 22/10/2026

Tudo o que a frente fiscal produziu até agora, para juntar com o repositório "PSC" (`sf_tse`).
Só método, código e exemplos fictícios. **Nenhum dado real.**

## Conteúdo

| Arquivo | O que é | Versão |
|---|---|---|
| `Protocolo_Verificacao_v2.md` | Regras do método (rascunho, ainda não congelado) | 2.0 |
| `Fontes_Publicas_Cruzamento.md` | 10 fontes oficiais e como arquivar cada consulta | 22/10 |
| `Controle_Verificacao.xlsx` | Planilha de controle **vazia** (14 abas, incluindo Fontes) | v2 + Fontes |
| `laudo_f4.py` | Perícia de PDF, com diff de texto entre revisões | 1.2 |
| `modulo_f5.py` | Completude e cruzamento bancário × fiscal, com pseudonimização | 1.0 |
| `exemplos/` | Saídas geradas com dados **fictícios** | — |
| `docs/2026-10-22_Verificacao_Frente_Fiscal.pdf` | Documento de método, com o retrato desta data | 22/10 |
| `docs/esquema_verificacao.html` | Fluxograma e tabela de conformidade (abre no navegador) | 22/10 |
| `.gitignore` | Impede subir dados e saídas para o Git | — |
| `SHA256SUMS.txt` | Hash de cada arquivo deste pacote | — |

Fora do pacote, de propósito:
- `Protocolo_Verificacao_v1.md`: substituído pela v2.0. Não distribuir.
- Quadro de tarefas e Mesa da Coordenação: são páginas online que se atualizam sozinhas.

## Como juntar com o repositório "PSC"

O repositório tem uma refatoração da colega (`nucleo.py`) que este pacote não tem. Este pacote tem melhorias que o repositório não tem. Use esta tabela:

| Arquivo | Qual usar | O que fazer |
|---|---|---|
| `nucleo.py` | **repositório** | Manter. É a implementação única de SIMBA, hashes e checagens |
| `modulo_f5.py` | **repositório** (1.1) | Manter. A lógica é a mesma desta 1.0, só que usando o `nucleo.py` |
| `laudo_f4.py` | **juntar** | Partir da versão do repositório (1.1, usa `nucleo.py`) e trazer desta 1.2: o diff de texto entre revisões (`brutos/texto_revisoes_diff.txt`, com `import difflib`) e o registro da versão do `pdftotext`. Subir como 1.2 |
| `Protocolo_Verificacao_v2.md` | **repositório** | A versão do repositório é esta mais a menção ao `nucleo.py` na seção 10 e no Anexo A |
| `Controle_Verificacao.xlsx` | **este pacote** | Só esta tem a aba Fontes |
| `Fontes_Publicas_Cruzamento.md` | **este pacote** | Não existe no repositório |
| `exemplos/` | **gerar de novo** | Depois de juntar o laudo, rodar laudo e F5 nos dados fictícios para que os exemplos citem as versões finais |
| `docs/` | **este pacote** | Criar a pasta `docs/` no repositório |
| `.gitignore` | **este pacote** | Colocar na raiz do repositório antes do próximo commit |
| `kit_sigilo/` | **decisão da coordenação** | Remover do repositório ou manter isolado, marcado como fora do protocolo (§2.3, §10) |

Depois de juntar, atualize o README do repositório: objetivo, regra de não subir dados, mapa dos arquivos, aviso sobre o kit e como rodar cada ferramenta.

## Regras do repositório

- Sem dados reais: extratos, SIMBA, declarações, PDFs dos autos, planilha preenchida, saídas dos scripts, `segredo.key`. O `.gitignore` cobre os casos comuns, mas a responsabilidade é de quem faz o commit.
- O histórico do Git guarda tudo: um arquivo apagado depois continua recuperável.
- Repositório privado, só com membros da frente, todos com 2FA.

## Conferir a integridade do pacote

```bash
cd frente_fiscal_2026-10-22
shasum -a 256 -c SHA256SUMS.txt
```
