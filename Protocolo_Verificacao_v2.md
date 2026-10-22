# Protocolo de Verificação de Documentos Fiscais e Bancários — versão 2.0

> **Status:** RASCUNHO, ainda não congelado.
> **Prazo crítico:** este protocolo precisa ser congelado e publicado **antes** de o material ser divulgado nos autos. Se for congelado depois, o relatório deve dizer isso na seção de limitações.
> Os campos entre `[colchetes]` são preenchidos pelo Comitê de Método antes do congelamento. Depois de congelado, o texto não é editado: qualquer mudança gera uma nova versão (seção 18).

| Campo | Valor |
|---|---|
| Responsável | [nome público do movimento] |
| Versão | 2.0 |
| Data e hora do congelamento | [AAAA-MM-DD hh:mm, horário de Brasília] |
| SHA-256 deste arquivo congelado | publicado separadamente (Anexo B) |
| Versão anterior | 1.0, rascunho não congelado, **substituído integralmente** por esta versão |
| Contato para contestações técnicas | [e-mail do projeto] |

---

## 1. Finalidade

Este protocolo define, **antes de qualquer análise**, como o [movimento] vai verificar os documentos fiscais e bancários do senador Flávio Bolsonaro que se tornarem públicos, em especial os que ele próprio entregar à Justiça ao abrir voluntariamente o seu sigilo. Ele é publicado com data e hash para que qualquer pessoa possa conferir que o método não foi ajustado depois de conhecidos os resultados.

O [movimento] se compromete a publicar o resultado **qualquer que seja**, inclusive se os documentos se mostrarem íntegros, coerentes e completos.

## 2. Escopo

### 2.1 Frentes de análise
| Frente | Material |
|---|---|
| **Frente 1: Divulgação pública** | Arquivos que o senador, sua assessoria ou sua defesa divulgarem por canais próprios (site, perfis oficiais, notas à imprensa) |
| **Frente 2: Autos judiciais** | Documentos fiscais e bancários juntados aos autos de [número do processo / tribunal] em razão do afastamento voluntário do sigilo, **na parte que estiver pública** |

### 2.2 Período e escopo da autorização
- Janela de captura: de [data inicial] até [data de corte].
- Antes de analisar a Frente 2, a equipe registra **o que exatamente o titular autorizou**: instituições, contas, bases fiscais e período. Esse registro, com a folha dos autos, é a régua da completude (seção 9).

### 2.3 O que não entra
- Material obtido por vazamento, por acesso não autorizado a qualquer sistema, ou de partes do processo sob segredo de justiça, **mesmo que chegue por outro caminho**
- Registros telefônicos, dados de localização (ERB, GPS) e dados de comunicação de qualquer pessoa
- Identificação, perfil ou mapeamento de relações de terceiros (seção 11)
- Juízos sobre intenção, conduta ou responsabilidade de qualquer pessoa

### 2.4 Lista de itens
A lista dos itens analisados, com origem e hash, é fechada na data de corte e publicada com o relatório. Um item descoberto depois da data de corte entra numa rodada nova, sob este mesmo protocolo, e é identificado como tal.

## 3. Perguntas de verificação

| # | Pergunta | Unidade de análise | Método principal |
|---|---|---|---|
| P1 | **Integridade:** o arquivo foi alterado depois de gerado? | Arquivo | Análise estrutural (6.3, 6.5) |
| P2 | **Autenticidade:** o arquivo veio do emissor que alega? | Arquivo | Verificação criptográfica, cadeia de origem, referência (6.1, 6.2, 6.4) |
| P3 | **Coerência:** o conteúdo é consistente internamente, entre bases e com fontes públicas? | Arquivo e conjunto | Seções 7 e 8 |
| P4 | **Completude:** o conjunto entregue cobre tudo o que foi autorizado e o que as próprias bases indicam que existe? | **Conjunto** | Seção 9 |

P1 a P3 recebem resposta **por arquivo**. P4 recebe resposta **por conjunto** (por instituição, por base fiscal e geral), por natureza.

## 4. Classificação de origem

Todo item recebe uma classe de origem na custódia. A classe aparece no relatório junto de cada afirmação.

| Classe | Definição | Exemplo | Efeito |
|---|---|---|---|
| **A: Institucional** | Enviado pelo emissor (banco, Receita, cartório) **diretamente ao juízo**, sem passar pelo titular | Resposta do banco via SIMBA; resposta da Receita via INFOJUD; ofício de instituição | Pode chegar a "Autenticidade confirmada (origem institucional)" (seção 12) |
| **B: Juntado pelo titular** | Cópia de documento oficial juntada pela defesa ou divulgada pelo titular | Extrato em PDF, declaração impressa, informe de rendimentos | Passa pela perícia completa (seção 6) |
| **C: Produzido pela defesa** | Material elaborado pela própria defesa | Planilha-resumo, parecer contábil, nota explicativa | **Não é fonte primária.** Cada afirmação dele é tratada como alegação a ser conferida contra A ou B |

Se não for possível determinar a classe, o item é tratado como **B**, e isso é registrado.

## 5. Captura, custódia e segurança

### 5.1 Captura
- **Frente 1:** arquivamento da publicação (archive.org e/ou archive.today), captura de tela com data e hora, download sem abrir nem reexportar. Uma cópia que circulou por terceiros só é usada se for idêntica, pelo hash, a uma cópia de canal atribuível.
- **Frente 2:** download **direto do sistema do tribunal**, registrando o número do processo, o ID do documento, as folhas e o código de autenticação ou assinatura de cada peça. Cópias de terceiros não são usadas.

### 5.2 Custódia
1. SHA-256 e SHA-512 de cada arquivo **antes** de abri-lo.
2. Original em armazenamento somente leitura, com uma segunda cópia em outro local.
3. Cada versão de um documento é um item próprio. Nada é sobrescrito.
4. A análise usa só cópias de trabalho, e o hash de cada cópia é conferido com o do original.
5. Os hashes dos originais recebem carimbo de tempo verificável (OpenTimestamps ou carimbo ICP-Brasil).

### 5.3 Segurança (reforçada para dados bancários)
- A análise é feita em máquina dedicada, com disco criptografado e sem sincronização com nuvem pública.
- O acesso aos dados brutos é nominal, com autenticação em dois fatores e log, e restrito a Custódia, Perícia e Conteúdo.
- Dados brutos nunca saem do ambiente de análise. O que sai são laudos, agregados e matrizes já pseudonimizadas (seção 11).
- Resultados preliminares não saem do grupo antes do contraditório.

## 6. Perícia dos arquivos (P1 e P2)

Antes da execução, cada item recebe a lista dos testes aplicáveis ao seu tipo, registrada na planilha de controle. Um teste que não se aplica é registrado como "não aplicável", com o motivo.

### 6.1 Verificação criptográfica e de autenticação
- Documento com assinatura digital (inclusive peças do PJe, e-STF e similares): validação no verificador oficial do ITI, com o relatório anexado.
- Peça com código de autenticação do tribunal: consulta no sistema do tribunal, com a resposta salva.
- Documento com código de controle do emissor (certidões, comprovantes): consulta no site do emissor.

### 6.2 Comparação com referência
- **Declarações e recibos da Receita:** referência gerada no programa oficial do mesmo ano-calendário, com dados fictícios, pelo mesmo caminho de geração.
- **Extratos bancários em PDF:** referência obtida por um membro no **mesmo banco e mesmo canal** (aplicativo, internet banking, agência), de conta própria, com os dados pessoais tarjados antes de entrar no ambiente de análise.
- Itens comparados: produtor e versão nos metadados, fontes, estrutura de objetos, layout, cabeçalhos e rodapés, formatação numérica.

### 6.3 Análise estrutural de PDF
Feita com `laudo_f4.py` (versão e hash registrados no Anexo A) e, quando instaladas, exiftool, qpdf e poppler. São observados:
- atualizações incrementais e o que cada uma acrescentou ou substituiu
- produtor/criador e datas (Info e XMP)
- fontes, imagens e páginas sem camada de texto
- abrangência das assinaturas digitais
- elementos ativos

### 6.4 Cadeia de origem (classe A)
Para itens da classe A, registra-se a cadeia: o ofício ou a determinação do juízo, a resposta da instituição e a peça que a junta aos autos, cada uma com a folha e o código de autenticação.

### 6.5 Integridade de arquivos de dados (SIMBA e similares)
Arquivos de texto não têm metadados. A integridade é aferida pelo hash na custódia e pelas checagens internas de leiaute (Carta-Circular BACEN 3.454/2010):
- `CODIGO_CHAVE_EXTRATO` sem repetição
- todo registro de ORIGEM_DESTINO ligado a um lançamento existente
- soma de `VALOR_TRANSACAO` por lançamento igual a `VALOR_LANCAMENTO`
- saldo anterior + lançamento = saldo informado, por conta, na ordem do extrato
- datas válidas no formato do leiaute
- conta marcada com movimentação e com lançamentos no período

## 7. Coerência (P3)

### 7.1 Coerência interna
- Dígitos verificadores de CPF/CNPJ
- Somatórios e totais (rendimentos, deduções, base de cálculo, imposto)
- Tabela do IR correspondente ao ano
- Saldo de bens em 31/12 de um ano igual ao saldo inicial do ano seguinte
- Datas compatíveis com o calendário oficial de entrega

### 7.2 Cruzamento com fontes públicas
- TSE (DivulgaCandContas): declarações de bens de candidaturas
- Portal da Transparência do Senado Federal: remuneração
- Receita Federal: consulta pública de CNPJ e quadro societário
- Juntas Comerciais, Diários Oficiais e autos de processos públicos
- Outras fontes oficiais aprovadas pelo Comitê **antes** do uso, com registro em ata

Uma reportagem só serve como pista para chegar a um documento primário.

### 7.3 Cruzamento bancário × fiscal
| Base fiscal | Base bancária | Comparação |
|---|---|---|
| Saldo em conta corrente e aplicações em 31/12 (Bens e direitos) | Saldo do extrato da mesma conta em 31/12 | Igualdade, dentro da tolerância |
| Rendimentos recebidos do Senado Federal | Créditos identificados como remuneração | Soma anual compatível |
| Outros rendimentos declarados com fonte pagadora | Créditos da mesma fonte pagadora | Soma anual compatível |
| Dívidas e ônus (financiamentos, empréstimos) | Débitos das parcelas e crédito do valor contratado | Compatibilidade de valores e datas |
| Aquisição ou alienação de bens no ano | Saídas ou entradas de valor compatível próximas da data | Existência de contrapartida financeira |
| Total de rendimentos (tributáveis, isentos, exclusivos) | Total de créditos líquidos (seção 8, regra B2) | Diferença a explicar |

## 8. Regras de interpretação (definidas antes da análise)

### 8.1 Regras gerais de perícia
- **G1.** A ausência de metadados não indica adulteração. Ela é registrada como perda de rastreabilidade.
- **G2.** Um produtor diferente do programa oficial indica reexportação, que é perda de rastreabilidade e não adulteração, salvo se houver outro indício.
- **G3.** Só conta como indício de adulteração uma alteração de conteúdo: atualização incremental que modifica texto ou valores, texto sobreposto, ou trecho substituído por imagem num documento que deveria ser texto.
- **G4.** Uma atualização incremental que só acrescenta assinatura, carimbo do tempo, anotação ou metadados não é indício.

### 8.2 Regras de comparação de valores
- **V1. Tolerância de arredondamento:** diferenças de até [R$ 1,00] por campo são ignoradas.
- **V2.** Diferença de critério (por exemplo, custo de aquisição no IR × outro valor no TSE) não é divergência. Ela é descrita, mas não entra na matriz.
- **V3.** Valores de datas-base diferentes só são comparados quando é possível alinhar as datas.
- **V4.** Uma divergência entra na matriz quando: há fonte primária anexada, ela supera a tolerância, não se explica por V2 ou V3, e foi confirmada por um revisor diferente do analista.
- **V5. Gravidade:**
  - **Baixa:** irrelevante para o patrimônio ou a renda declarados
  - **Média:** relevante, mas com explicação plausível documentada
  - **Alta:** relevante e sem explicação plausível encontrada

### 8.3 Regras específicas de dados bancários
- **B1. Contas próprias:** transferências entre contas do mesmo titular (mesmo CPF) são excluídas do total de créditos e de débitos.
- **B2. Créditos que não são renda:** resgate de aplicação, estorno, devolução, crédito de empréstimo ou financiamento contratado e transferência entre contas próprias são classificados à parte, pela tabela de tipos de lançamento do leiaute (CNAB-240), e não somam como renda.
- **B3. Créditos × rendimentos:** a comparação do total de créditos com os rendimentos declarados só é feita depois de B1 e B2. Uma diferença é registrada como **"diferença a explicar"**, e nunca como "renda omitida" ou expressão equivalente.
- **B4. Ordem de lançamentos:** quebra de saldo explicada apenas pela ordem dos lançamentos do mesmo dia não é divergência.
- **B5. Contraparte não identificada** (saque em espécie, depósito sem identificação) é registrada como tal, sem presunção sobre a origem ou o destino.
- **B6. Cobertura total:** as checagens 6.5 e os cruzamentos 7.3 são aplicados a **todos** os registros, não por amostragem. Se algum teste manual exigir amostragem, o critério de seleção é registrado em ata **antes** de se olhar o resultado.

## 9. Completude (P4)

### 9.1 Testes
| Teste | Pergunta |
|---|---|
| **C1. Contas declaradas** | Cada conta ou aplicação em "Bens e direitos" do IR, dentro do escopo autorizado, tem extrato entregue? |
| **C2. Contas referidas** | Cada conta do próprio titular que aparece como origem ou destino em transferências tem extrato entregue? |
| **C3. Cobertura de período** | Os extratos de cada conta cobrem todo o período autorizado, sem meses faltando? |
| **C4. Continuidade de saldo** | O saldo final de cada extrato é igual ao saldo inicial do seguinte, dentro da tolerância? |
| **C5. Bases fiscais** | Todas as bases fiscais autorizadas (por exemplo: DIRPF, DIRF, e-Financeira, DIMOB, DOI) foram entregues para todo o período? |
| **C6. Coerência com o escopo** | O que foi entregue corresponde ao que foi autorizado, sem omissão nem substituição de período? |

### 9.2 Regras
- **L1.** Uma lacuna só é registrada **dentro do escopo autorizado** (2.2). O que está fora do escopo é descrito como "fora do escopo da autorização", sem juízo.
- **L2.** Conta encerrada, inexistente no período ou sem movimento, quando documentada nos autos, explica a lacuna.
- **L3.** Uma lacuna atribuível a falha da instituição ou do juízo, e não do titular, é descrita como tal.

### 9.3 Escala de completude (por conjunto)
| Resultado | Critério |
|---|---|
| **Completo** | C1 a C6 sem lacunas |
| **Lacunas explicadas** | Todas as lacunas têm explicação documentada (L2 ou L3) |
| **Lacunas não explicadas** | Pelo menos uma lacuna dentro do escopo sem explicação documentada |
| **Não avaliável** | O escopo da autorização não pôde ser determinado |

## 10. Uso de ferramentas automatizadas

- Toda ferramenta é registrada no Anexo A com versão e hash.
- Do kit de leitura de dados de sigilo, são usados **apenas** o leitor do leiaute SIMBA, as funções de normalização (CPF/CNPJ, valores, datas) e as checagens de consistência (6.5), **com a pseudonimização da seção 11 aplicada na importação**.
- **Não são usados** os módulos de mapeamento de pessoas, de cruzamento de telefones, de linha do tempo nem de dados telefônicos.
- Resultados automáticos são observações. Toda observação que embasar uma divergência ou lacuna passa pela revisão cega.

## 11. Terceiros e dados pessoais

O afastamento do sigilo pelo titular **não** afasta o sigilo de quem transacionou com ele.

- **T1. Pseudonimização na importação.** Todo CPF de contraparte pessoa física é substituído, já na importação, por um identificador `PF-xxxxxxxx`, gerado por HMAC-SHA256 com um segredo guardado só pela Custódia. Os nomes de pessoas físicas não são importados. Os analistas trabalham só com os identificadores.
- **T2. Publicação por agregados.** O relatório só publica agregados (por exemplo: "R$ X recebidos de N pessoas físicas distintas"), nunca uma lista de contrapartes.
- **T3. Identificação excepcional.** Uma contraparte só é identificada se isso for indispensável para responder P3 ou P4, com decisão unânime do Comitê **e** parecer favorável do Jurídico, registrados em ata. Órgãos públicos e a própria fonte pagadora declarada no IR podem ser nomeados sem esse procedimento.
- **T4. Pessoas jurídicas** podem ser nomeadas quando já constarem do IR do titular ou de fonte pública, e quando a menção for necessária para a conclusão.
- **T5. Tarjamento.** Dependentes, endereços, números de conta e documentos de terceiros são tarjados em todo material publicado.
- **T6. Proibição de perfilamento.** Fica vedado montar rede de relacionamentos, linha do tempo ou perfil de qualquer terceiro.

## 12. Escala de veredito (por arquivo: P1 a P3)

O relatório usa exatamente os termos abaixo.

| Veredito | Critério necessário |
|---|---|
| **Autenticidade confirmada** | Verificação criptográfica (6.1) válida e íntegra, ou código oficial conferido |
| **Autenticidade confirmada (origem institucional)** | Classe A com cadeia de origem completa (6.4) e peças autenticadas pelo tribunal |
| **Íntegro e consistente** | Nenhum indício pela regra G3, estrutura compatível com a referência (6.2) ou checagens 6.5 sem falhas, e nenhuma divergência de gravidade alta |
| **Sem sinais de adulteração, não confirmável** | Nenhum indício pela regra G3, mas sem referência compatível ou sem verificação oficial possível |
| **Inconsistências relevantes** | Uma ou mais divergências de gravidade alta, sem indício técnico de alteração do arquivo |
| **Indícios técnicos de alteração** | Pelo menos um indício pela regra G3, confirmado em revisão cega, sem explicação inocente aceita pelo Comitê |
| **Não verificável** | Material insuficiente para os testes |
| **Alegação da defesa (classe C)** | Material da classe C: não recebe veredito de autenticidade; suas afirmações são conferidas uma a uma contra fontes A ou B |

Um mesmo arquivo pode ter um veredito favorável em P1 e P2 e uma nota de inconsistência em P3. O relatório mostra as respostas separadas.

## 13. Governança e decisão

### 13.1 Papéis
| Papel | Função |
|---|---|
| Coordenação | Prazos e comunicação externa |
| Comitê de Método (3 membros) | Guarda o protocolo e decide vereditos e completude |
| Custódia | Captura, hashes, armazenamento, log e o segredo da pseudonimização |
| Perícia técnica | Seção 6 |
| Conteúdo fiscal e bancário | Seções 7 a 9 |
| Red Team | Busca a melhor explicação inocente para cada achado |
| Jurídico | Escopo da autorização, segredo de justiça, terceiros (T3) e redação final |

### 13.2 Regras
1. **Conflito de interesse:** quem tem filiação partidária ativa, cargo ou atuação em campanha não integra o Comitê de Método nem o Red Team. Todos os membros assinam uma declaração.
2. **Separação de funções:** quem executou um teste não o revisa nem vota o veredito dele.
3. **Revisão cega:** cada teste de 6.2, 6.3, 6.5, cada divergência e cada lacuna são refeitos por uma segunda pessoa que não vê o primeiro resultado. Resultados diferentes vão ao Comitê.
4. **Quórum:**
   - "Indícios técnicos de alteração" e "Lacunas não explicadas": **unanimidade** (3 de 3)
   - Identificação de terceiro (T3): unanimidade e parecer do Jurídico
   - Demais decisões: maioria (2 de 3)
5. **Objeções abertas:** nenhum veredito é emitido enquanto houver objeção do Red Team sem resposta escrita para aquele item ou conjunto.
6. **Registro:** cada decisão fica em ata, com os votos e a justificativa.

## 14. Red Team

- O Red Team recebe os laudos, a matriz de divergências e a matriz de lacunas **depois** da revisão cega.
- Para cada achado, ele apresenta por escrito a explicação inocente mais forte possível.
- As células técnicas respondem ponto a ponto, aceitando ou rejeitando a explicação com justificativa.
- O memorial do Red Team e as respostas são publicados no relatório.

## 15. Contraditório

1. Antes da publicação, os achados são enviados por escrito à defesa do senador, por [canal oficial].
2. **Prazo:** [72] horas a partir do envio.
3. Os achados citam o processo, o ID do documento e as folhas.
4. Para cada lacuna, pergunta-se se o documento existe e se pode ser juntado.
5. A resposta, ou a falta dela, é publicada no relatório. Um documento juntado depois disso passa pelas seções 5 a 9, e os resultados são revistos.

## 16. Publicação

O relatório contém:
1. Resumo com os vereditos por arquivo (P1 a P3) e o resultado de completude por conjunto (P4)
2. Link para este protocolo e o hash dele
3. Lista dos itens com classe de origem, referência nos autos ou URL arquivada, e hash
4. Laudos técnicos com comandos e saídas, suficientes para reproduzir os testes
5. Matriz de divergências e matriz de lacunas, já pseudonimizadas
6. Memorial do Red Team e as respostas
7. Resposta do contraditório
8. Limitações e desvios do protocolo (seção 18)

**Linguagem:** o texto descreve evidências ("o extrato não cobre o período X", "o valor difere da fonte Y em Z") e não atribui intenção nem conduta a ninguém. Expressões como "omitiu", "escondeu" ou "fraudou" não são usadas.

## 17. Correções e reanálise

- Qualquer pessoa pode enviar uma contestação técnica para [e-mail do projeto].
- Uma contestação que traga evidência nova é analisada sob este protocolo, e o resultado é publicado.
- Erros confirmados são corrigidos no próprio relatório, com nota datada e destaque equivalente ao do conteúdo original, em até [5] dias.

## 18. Desvios e versões

- Qualquer desvio deste protocolo durante a análise é registrado em ata, com o motivo, e **publicado na seção de limitações do relatório**.
- Uma mudança de regra gera nova versão (2.1, 3.0…), com novo hash, a referência ao hash desta versão e a lista das mudanças.
- Uma regra alterada depois que algum resultado já é conhecido **não se aplica retroativamente** sem ser apontada como desvio.

## 19. Retenção e descarte

- Dados brutos bancários e fiscais: guardados por [prazo] após a publicação, ou enquanto houver contestação ou processo pendente. Depois disso, descarte seguro, registrado em ata.
- O segredo da pseudonimização é destruído junto com os dados brutos.
- Laudos, matrizes pseudonimizadas e atas: guardados por tempo indeterminado.

---

## Anexo A: ferramentas e comandos

| Ferramenta | Versão | SHA-256 |
|---|---|---|
| laudo_f4.py | [1.x] | [hash] |
| módulo de leitura SIMBA e checagens (derivado do kit) | [versão] | [hash] |
| exiftool, qpdf, poppler | [versões] | — |

```bash
# hashes (antes de abrir o arquivo)
shasum -a 256 ARQUIVO
shasum -a 512 ARQUIVO

# laudo técnico de PDF
python3 laudo_f4.py COPIA.pdf --id DOC-001 --executor M01 --hash-esperado <sha256> [--referencia REF.pdf]

# carimbo de tempo do hash
ots stamp ARQUIVO
```

## Anexo B: como congelar e publicar este protocolo

1. Preencher todos os campos entre colchetes e apagar a linha "Status: RASCUNHO".
2. Aprovar o texto em ata do Comitê de Método.
3. Calcular o hash do arquivo final:
   ```bash
   shasum -a 256 Protocolo_Verificacao_v2.md
   ```
4. Gerar um carimbo de tempo para o arquivo (`ots stamp Protocolo_Verificacao_v2.md`).
5. Publicar **ao mesmo tempo**: o arquivo, o hash e o comprovante do carimbo, em pelo menos dois canais públicos (por exemplo, o site e um repositório público com histórico).
6. Arquivar as publicações no archive.org.
7. Só depois disso começar a captura.

## Anexo C: mudanças em relação ao rascunho 1.0

| Seção | Mudança |
|---|---|
| 2 | Duas frentes (divulgação pública e autos); registro do escopo da autorização; exclusão de dados telefônicos, de localização e de partes em segredo de justiça |
| 3 | Nova pergunta P4 (completude), avaliada por conjunto |
| 4 | Nova classificação de origem A/B/C |
| 5 | Captura nos autos direto do sistema do tribunal; segurança reforçada |
| 6 | Autenticação de peças judiciais; referência para extratos bancários; cadeia de origem; integridade de arquivos SIMBA |
| 7 | Cruzamento bancário × fiscal |
| 8 | Regras renumeradas (G, V) e novas regras bancárias (B1 a B6) |
| 9 | Nova seção de completude, com escala própria |
| 10 | Uso restrito de ferramentas automatizadas |
| 11 | Nova seção sobre terceiros, com pseudonimização obrigatória |
| 12 | Novos vereditos "origem institucional" e "alegação da defesa" |
| 13 | Unanimidade também para "lacunas não explicadas" e para identificar terceiros |
| 19 | Nova seção de retenção e descarte |
