# Relatório F5: CONJ-TESTE

> Observações automáticas. Lacunas e divergências aqui são **candidatas**: passam pela revisão cega, pelo Red Team e pelo Comitê (protocolo v2.0, seções 9, 13 e 14) antes de qualquer conclusão.

- Script: `modulo_f5.py v1.0` (SHA-256 `0ebd09eed5586f0672e366e32a6c3b719a7dce4422c019aed99d88f26cbcd7f2`)
- Execução (UTC): 2026-10-22 18:25:32
- Escopo: 2023-01-01 a 2023-12-31; instituições: ['104', '1', '237']; referência: processo ficticio, fls. 1
- Tolerância (V1): R$ 1,00
- Arquivos SIMBA: 4; lançamentos: 73; origens/destinos: 60; contrapartes PF pseudonimizadas: 4

## Completude (P4)

| Conjunto | Resultado automático |
|---|---|
| bancário | Lacunas encontradas (explicação a verificar: L2/L3) |
| fiscal | Lacunas encontradas (explicação a verificar: L2/L3) |

| Teste | Item | Situação | Detalhe |
|---|---|---|---|
| C1 contas declaradas | conta 104|1000|123456 (IR 2023, CC CAIXA) | **ok** | extrato entregue |
| C1 contas declaradas | conta 1|2000|777 (IR 2023, CC BB) | **ok** | extrato entregue |
| C1 contas declaradas | conta 237|3000|555 (IR 2023, CC BRADESCO) | **lacuna** | conta declarada no IR, dentro do escopo, sem extrato entregue (verificar L2/L3) |
| C1 contas declaradas | conta 341|1|998877 (IR 2023, CC ITAU) | **fora do escopo** | instituição fora da autorização (L1) |
| C2 contas referidas | conta 237|3000|555 | **lacuna** | 1 transferência(s) do/para o próprio titular envolvem esta conta, que não foi entregue |
| C2 contas referidas | conta 341|1|998877 | **fora do escopo** | 1 transferência(s) do/para o titular; instituição fora da autorização (L1) |
| C3 cobertura de período | conta 104|1000|123456 | **ok** | lançamentos em todos os meses de 01/2023 a 12/2023 |
| C4 continuidade de saldo | conta 104|1000|123456 | **ok** | saldo contínuo em todo o extrato |
| C3 cobertura de período | conta 1|2000|777 | **verificar** | 1 mês(es) sem lançamento: 06/2023. Pode ser conta parada; ver C4 para saber se o saldo confirma. |
| C4 continuidade de saldo | conta 1|2000|777 | **lacuna** | 1 quebra(s) de saldo não explicadas pela ordem do dia (B4): entre 18/05/2023 e 08/07/2023: diferença de saldo de -R$ 200,00 (indica débito não listado). Indica lançamentos ou período faltando. |
| C5 bases fiscais | DIRPF | **ok** | entregue em todos os anos autorizados |
| C5 bases fiscais | DIRF | **ok** | entregue em todos os anos autorizados |
| C5 bases fiscais | EFINANCEIRA | **lacuna** | anos autorizados sem entrega: 2023 |
| C6 coerência com o escopo | instituição 104 | **ok** | dados entregues |
| C6 coerência com o escopo | instituição 1 | **ok** | dados entregues |
| C6 coerência com o escopo | instituição 237 | **lacuna** | instituição autorizada sem nenhum dado entregue (verificar se é falha da instituição: L3) |
| C6 coerência com o escopo | período dos lançamentos | **ok** | lançamentos de 05/01/2023 a 20/12/2023; 0 fora do período autorizado |

## Integridade dos arquivos SIMBA (6.5)

| Checagem | Situação | Qtd | Detalhe |
|---|---|---|---|
| 6.5 chave do extrato sem repetição | **ok** | 0 | CODIGO_CHAVE_EXTRATO repetido |
| 6.5 origem/destino ligado a lançamento | **ok** | 0 | ORIGEM_DESTINO sem lançamento |
| 6.5 soma origem/destino = lançamento | **ok** | 0 | soma de VALOR_TRANSACAO diferente de VALOR_LANCAMENTO |
| 6.5 lançamento com origem/destino | **observação** | 13 | lançamento sem registro em ORIGEM_DESTINO (o leiaute pede ao menos 1) |
| 6.5 saldo fecha (B4 aplicada) | **falha** | 1 | saldo anterior + lançamento ≠ saldo informado; 0 quebra(s) explicada(s) só pela ordem do dia (B4) |
| 6.5 datas válidas | **ok** | 0 | DATA_LANCAMENTO fora do formato DDMMAAAA |
| 6.5 conta com movimentação tem lançamentos | **ok** | 0 | MOVIMENTACAO_CONTA=1 sem lançamentos: - |

## Cruzamento bancário × fiscal (7.3)

| Tipo | Ano | Item | Fiscal | Bancário | Diferença | Dentro da tolerância |
|---|---|---|---|---|---|---|
| Saldo em 31/12 | 2023 | conta 104|1000|123456 | R$ 82.000,00 | R$ 82.000,00 | R$ 0,00 | sim |
| Saldo em 31/12 | 2023 | conta 1|2000|777 | R$ 2.400,00 | R$ 1.900,00 | R$ 500,00 | não |
| Saldo em 31/12 | 2023 | conta 237|3000|555 | R$ 10.000,00 | - | - | - |
| Saldo em 31/12 | 2023 | conta 341|1|998877 | R$ 4.000,00 | - | - | - |
| Rendimentos × créditos da fonte | 2023 | 11222333000181 FONTE PAGADORA FICTICIA | R$ 95.000,00 | R$ 95.000,00 | R$ 0,00 | sim |
| Pagamentos de dívida declarada | 2023 | 33444555000122 FINANCIAMENTO IMOVEL | R$ 36.000,00 | R$ 36.000,00 | R$ 0,00 | sim |
| Créditos líquidos × rendimentos (B3) | 2023 | total do ano | R$ 95.000,00 | R$ 116.300,00 | -R$ 21.300,00 | não |

Não automatizado: aquisição e alienação de bens × contrapartida financeira (7.3, última linha). Fazer à mão, a partir de movimentos_pseudonimizados.csv.

## Arquivos gerados

| Arquivo | Uso | Pode publicar? |
|---|---|---|
| relatorio_f5.md | este resumo | após revisão |
| completude.csv / lacunas_candidatas.csv | P4 | após revisão |
| cruzamentos.csv / divergencias_candidatas.csv | P3; colar na aba Divergencias | após revisão |
| checagens_simba.csv | 6.5 | sim |
| agregados_publicaveis.csv | T2: só totais e contagens | sim |
| movimentos_pseudonimizados.csv | trabalho interno | **não** (T2) |
| execucao.json | hashes de entradas e do script, para reproduzir | sim |
