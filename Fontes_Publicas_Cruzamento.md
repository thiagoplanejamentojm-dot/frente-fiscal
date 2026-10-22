# Fontes públicas de cruzamento — guia de consulta e arquivamento

> Complementa o protocolo v2.0, seção 7.2. **As fontes da seção 3 precisam ser aprovadas em ata do Comitê antes do primeiro uso** (§7.2, último item). Fonte nova durante a análise = nova ata, antes de usar.
> Endereços conferidos em 22/10/2026. Sites mudam: se um link quebrar, registre o endereço novo na ata.

---

## 1. Regras de uso

1. **Só fonte primária e oficial.** Reportagem, livro, post ou site agregador ("consulta CNPJ grátis", "dados de CPF") serve no máximo como **pista** para chegar ao documento oficial. Nunca entra como fonte de cruzamento.
2. **Arquivar antes de usar.** Nenhum dado entra na matriz de divergências sem a captura arquivada e o hash registrado (seção 4).
3. **Só dados do titular.** A consulta é sobre o patrimônio, a renda e as empresas do próprio titular. Não se pesquisa familiar, assessor, sócio ou contraparte, salvo decisão unânime do Comitê com parecer do Jurídico (§11, T3).
4. **Sem atalhos.** Proibido: burlar CAPTCHA, usar robôs contra os termos de uso de um site, usar credenciais de terceiros, comprar dados de serviços de "consulta de CPF". Onde há CAPTCHA, a consulta é manual.
5. **Fonte paga é decisão do grupo.** Certidões de cartório e de Junta Comercial são pagas. O gasto e o responsável pelo pedido são aprovados em ata.
6. **Dado faltando vira pedido pela LAI**, não suposição. Registre o protocolo do pedido.

---

## 2. Mapa: cada cruzamento e onde buscar

| Cruzamento (§7.3) | Fonte | Prioridade |
|---|---|---|
| Bens declarados ao IR × bens declarados ao TSE | TSE: bens de candidatos (3.1) | Alta |
| Rendimentos do Senado × créditos do Senado no extrato | Senado: remuneração (3.2) e benefícios/cota (3.3) | Alta |
| Rendimentos da ALERJ (até jan/2019) | ALERJ: transparência ou LAI (3.4) | Média |
| Participações societárias declaradas × registros | Receita: CNPJ e QSA (3.5); Junta Comercial (3.6) | Alta |
| Imóveis declarados × registro de imóveis | ONR/SAEC (3.7) | Alta (paga) |
| Atos oficiais (nomeações, contratos, publicações) | Diários oficiais (3.8) | Média |
| Fatos já apurados em juízo | Consulta processual e DataJud (3.9) | Média |
| Financiamentos, veículos, saldos bancários | **Sem fonte pública.** Só os autos e o próprio IR | — |

**Atenção a um detalhe que muda o cruzamento B3:** reembolsos da cota parlamentar e auxílio-moradia são pagos pelo Senado e entram na conta como crédito, mas não são remuneração tributável. Antes de comparar créditos do Senado com rendimentos, separe esses valores usando as bases 3.3. Sem isso, a diferença vai parecer maior do que é.

---

## 3. Fontes

### 3.1 TSE — bens declarados por candidatos
- **Consulta individual:** DivulgaCandContas — https://divulgacandcontas.tse.jus.br
  Página de cada candidatura, com a lista de bens declarados, certidões e prestação de contas.
- **Arquivo aberto (preferir este):** Portal de Dados Abertos do TSE — https://dadosabertos.tse.jus.br
  Conjunto "Candidatos <ano>", recurso "Bens de candidatos". Arquivo ZIP com CSV de todas as UFs, no padrão
  `https://cdn.tse.jus.br/estatistica/sead/odsele/bem_candidato/bem_candidato_<ano>.zip`
- **Anos:** todas as eleições em que o titular concorreu. Inclui a de 2026, se houver registro, que é a mais próxima das declarações em análise.
- **Cuidados:**
  - O valor declarado ao TSE segue critério do candidato e pode diferir do IR sem irregularidade (regra V2).
  - A data-base da declaração ao TSE não é 31/12 (regra V3).
  - A data de geração do arquivo vem dentro do próprio ZIP: anote-a.
- **Como arquivar:** baixar o ZIP sem descompactar, calcular o SHA-256 e guardar o original. Filtrar a linha do titular numa cópia.

### 3.2 Senado — remuneração do senador
- **Onde:** Portal da Transparência do Senado — https://www12.senado.leg.br/transparencia
  Seção de remuneração de senadores e servidores.
- **Cuidados:** a consulta individual pode pedir identificação de quem consulta. Use a conta do projeto, nunca a de um membro, e registre isso no log.
- **Cruzamento:** soma anual de subsídio bruto, descontos (IR, previdência) e líquido × "Rendimentos recebidos de PJ — Senado Federal" no IR × créditos do Senado no extrato.

### 3.3 Senado — cota parlamentar e outros benefícios
- **Dados abertos do Senado, seção Senadores:** https://www12.senado.leg.br/dados-abertos/administrativo/senadores
  - Cotas para Exercício da Atividade Parlamentar (CEAPS): https://www12.senado.leg.br/dados-abertos/administrativo/senadores/cotas-para-exercicio-da-atividade-parlamentar
  - Outros benefícios (auxílio-moradia, imóvel funcional): https://www12.senado.leg.br/dados-abertos/administrativo/senadores/outros-beneficios-de-senadores
- **Uso:** separar créditos do Senado que são reembolso ou indenização (não renda) dos que são subsídio. Ver o aviso da seção 2.

### 3.4 ALERJ — período de deputado estadual
- **Onde:** Portal da Transparência da ALERJ — https://www.alerj.rj.gov.br (seção Transparência).
- **Cuidados:** a remuneração individualizada de anos antigos pode não estar online. Nesse caso, pedido pela LAI à ALERJ, com o protocolo registrado.
- **Uso:** só se o período analisado incluir anos anteriores a fev/2019.

### 3.5 Receita Federal — empresas e quadro societário
- **Comprovante de inscrição de um CNPJ:** consulta pública da Receita (tem CAPTCHA, então é manual). Salvar o comprovante em PDF.
- **Base aberta do CNPJ:** dados abertos da Receita Federal, com arquivos mensais em CSV: empresas, estabelecimentos e **Sócios** (QSA). Acesso pelo Portal de Dados Abertos do governo federal (https://dados.gov.br), conjunto "Cadastro Nacional da Pessoa Jurídica — CNPJ".
- **Cuidados:**
  - Na base aberta, o CPF do sócio vem **parcialmente mascarado**. Confirme o vínculo por nome **e** pelos dígitos visíveis **e** pelo CNPJ declarado no IR, nunca só pelo nome.
  - Use espelhos não oficiais (Brasil.IO e similares) só como pista.
- **Uso:** cada participação em "Bens e direitos" do IR (códigos de quotas/ações) × existência da empresa, situação cadastral, data de entrada e saída do sócio e capital social.

### 3.6 Junta Comercial — atos societários
- **Onde:** JUCERJA (Rio de Janeiro) — https://www.jucerja.rj.gov.br , ou a Junta da UF da empresa.
- **O quê:** contrato social e alterações, com capital, quotas e datas de entrada e saída.
- **Cuidados:** certidões e cópias são pagas (decisão do grupo, regra 5). A certidão digital costuma ter código de autenticação: valide e registre (§6.1).

### 3.7 Registro de imóveis — ONR / SAEC
- **Onde:** https://registradores.onr.org.br (plataforma nacional dos cartórios de registro de imóveis).
- **Serviços:**
  - **Visualização de matrícula:** mais barata e informativa, sem valor de certidão.
  - **Certidão digital de matrícula:** assinada com certificado ICP-Brasil, então é validável (§6.1).
  - **Pesquisa qualificada por CPF:** localiza imóveis em nome de um CPF. Usar só para o **titular**, com aprovação em ata.
- **Cuidados:** todos os serviços são pagos. A visualização e a certidão exigem o número da matrícula e o cartório, que normalmente vêm dos autos ou do IR.
- **Uso:** cada imóvel em "Bens e direitos" × matrícula (titularidade, data e valor da aquisição, ônus como hipoteca ou alienação fiduciária) × "Dívidas e ônus" do IR.

### 3.8 Diários oficiais
- **União:** https://www.in.gov.br
- **Estado do RJ:** Imprensa Oficial do RJ — https://www.ioerj.com.br
- **Municípios:** Querido Diário (Open Knowledge Brasil) — https://queridodiario.ok.org.br , com busca em diários municipais.
- **Uso:** confirmar datas e fatos públicos (nomeações, contratos, publicações societárias exigidas por lei).

### 3.9 Processos judiciais
- **Consulta processual** de cada tribunal (STF, STJ, TJRJ, TRF2 etc.). As peças públicas trazem código de autenticação (§6.1).
- **DataJud (CNJ) — API pública:** https://www.cnj.jus.br/sistemas/datajud/api-publica/
  Metadados de processos públicos (capa e movimentos). Processos em segredo não aparecem. Exige a chave pública divulgada pelo CNJ: https://datajud-wiki.cnj.jus.br/api-publica/
- **Uso:** só fatos já registrados em decisões ou peças públicas. Nada sob segredo de justiça (§2.3).

### 3.10 Pedidos pela Lei de Acesso à Informação
- **Federal:** Fala.BR — https://falabr.cgu.gov.br
- **Senado:** Serviço de Informação ao Cidadão do Senado, pelo portal de transparência.
- **ALERJ / Estado do RJ:** SIC de cada órgão.
- **Registro:** número do protocolo, data, texto do pedido, prazo legal (20 dias, prorrogáveis por mais 10) e resposta. Cada resposta é arquivada como fonte (seção 4).

---

## 4. Como arquivar cada consulta

Toda consulta recebe um ID (`F-001`, `F-002`…) e segue estes passos **no momento da consulta**:

### 4.1 Páginas web (HTML)
1. **Arquivo público:**
   - Wayback Machine: https://web.archive.org/save (cole a URL)
   - e/ou archive.today: https://archive.ph
   - Guarde o link gerado.
   - **Exceção:** não envie para arquivo público uma URL que contenha CPF, nome de terceiro ou outro dado pessoal no endereço ou nos parâmetros. Nesses casos, só arquivo local.
2. **Cópia local:** salve a página completa ("Salvar como → Página web, completa") e faça uma captura de tela com o relógio do sistema visível.
3. **Hash:** `shasum -a 256` de cada arquivo salvo.

Páginas dinâmicas (sistemas que montam a tela com JavaScript, como o DivulgaCandContas) costumam sair em branco no arquivo público. Nesses casos, prefira o arquivo de dados abertos equivalente, que é estático e verificável por hash. Se não houver, valem a captura de tela e a página salva.

### 4.2 Arquivos de dados (ZIP, CSV)
1. Baixe o arquivo original **sem descompactar nem abrir no Excel** (o Excel altera o arquivo ao salvar).
2. `shasum -a 256` e `shasum -a 512` do original.
3. Registre a URL exata e a data de geração informada pela fonte.
4. Trabalhe só numa cópia. O filtro que extrai a linha do titular é registrado como comando reproduzível.

### 4.3 Documentos com validação (certidões, peças judiciais, matrículas)
1. Salve o PDF original.
2. Valide a assinatura (validar.iti.gov.br) ou o código de autenticação no site do emissor e salve o resultado.
3. Hash do PDF e do comprovante de validação.

### 4.4 Registro no log
Cada consulta vira uma linha no log de fontes (sugestão: nova aba "Fontes" na planilha de controle):

| Campo | Exemplo (fictício) |
|---|---|
| ID da consulta | F-001 |
| Data e hora | 23/10/2026 10:42 |
| Consultado por (codinome) | M04 |
| Fonte (seção deste guia) | 3.1 TSE — bens de candidatos |
| URL exata | https://cdn.tse.jus.br/…/bem_candidato_2022.zip |
| Parâmetros da consulta | ano 2022; filtro pelo número do candidato |
| Arquivo local | fontes/F-001/bem_candidato_2022.zip |
| SHA-256 | (hash) |
| Link de arquivo público | https://web.archive.org/web/… ou "não aplicável (arquivo de dados)" |
| Aprovada na ata | A-004 |
| Usada em | D-012 (aba Divergencias) |
| Observações | data de geração dentro do ZIP: 15/10/2026 |

---

## 5. Antes da primeira consulta

- [ ] Comitê aprova em ata a lista de fontes da seção 3 (e o gasto com as pagas).
- [ ] Definir a conta institucional do projeto para portais que pedem identificação.
- [ ] Criar a pasta `fontes/` no armazenamento da custódia, com uma subpasta por consulta.
- [ ] Criar a aba "Fontes" na planilha de controle (campos da seção 4.4).
- [ ] Combinar quem faz cada fonte: o mesmo analista não revisa a própria coleta (§13.2).
