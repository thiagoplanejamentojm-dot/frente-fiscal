#!/usr/bin/env python3
"""Módulo F5: completude (P4) e cruzamento bancário × fiscal (P3), protocolo v2.0, seções 6.5, 7.3, 8.3, 9 e 11.

uso:
    # 1. a Custódia gera o segredo da pseudonimização (uma vez; guardar fora do ambiente dos analistas)
    python3 modulo_f5.py gerar-segredo --arquivo segredo.key

    # 2. criar os modelos de entrada (escopo da autorização e dados do IR transcritos dos autos)
    python3 modulo_f5.py modelos --pasta entradas

    # 3. rodar a análise
    python3 modulo_f5.py analisar --simba autos/simba --entradas entradas --titular-cpf 00000000000 \
        --segredo segredo.key --id CONJ-01 --saida f5

    # consulta da Custódia: qual pseudônimo corresponde a um CPF (para o procedimento T3)
    python3 modulo_f5.py pseudonimo --segredo segredo.key --cpf 00000000000

pseudonimização (seção 11, T1), feita NA IMPORTAÇÃO, antes de qualquer dado chegar à análise:
    - CPF de pessoa física que não é o titular  -> PF-XXXXXXXXXX (HMAC-SHA256 com o segredo)
    - nomes de pessoas físicas, documentos de identidade, endereços, telefones, renda,
      contas de terceiros, endossantes e textos livres (descrição, observação, local) -> descartados
    - a descrição do lançamento é usada só para classificar (resgate, estorno, empréstimo...)
      e depois descartada, porque costuma trazer nome de quem pagou ou recebeu
    - CNPJ e nome de pessoa jurídica são mantidos (T4); o titular é mantido

nada aqui conclui irregularidade: as saídas são candidatos a lacuna e a divergência,
que passam pela revisão cega, pelo Red Team e pelo Comitê (seções 13 e 14).

leiaute SIMBA e tabela de tipos de lançamento derivados do kit_sigilo (simba.py).
só usa a biblioteca padrão do Python (3.9+)."""
import argparse
import csv
import hashlib
import hmac
import json
import re
import secrets
import sys
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

VERSAO = "1.0"

# ---------------------------------------------------------------- leiaute SIMBA

LEIAUTE = {
    "AGENCIAS": ["NUMERO_BANCO", "NUMERO_AGENCIA", "NOME_AGENCIA", "ENDERECO_LOGRADOURO", "ENDERECO_CIDADE",
                 "ENDERECO_UF", "ENDERECO_PAIS", "ENDERECO_CEP", "TELEFONE_AGENCIA", "DATA_ABERTURA_AGENCIA",
                 "DATA_FECHAMENTO_AGENCIA"],
    "CONTAS": ["NUMERO_BANCO", "NUMERO_AGENCIA", "NUMERO_CONTA", "TIPO_CONTA", "DATA_ABERTURA_CONTA",
               "DATA_ENCERRAMENTO_CONTA", "MOVIMENTACAO_CONTA"],
    "TITULARES": ["NUMERO_BANCO", "NUMERO_AGENCIA", "NUMERO_CONTA", "TIPO_CONTA", "TIPO_TITULAR",
                  "PESSOA_INVESTIGADA", "TIPO_PESSOA_TITULAR", "CPF_CNPJ_TITULAR", "NOME_TITULAR",
                  "NOME_DOC_IDENTIFICACAO", "NUMERO_DOC_IDENTIFICACAO", "ENDERECO_LOGRADOURO", "ENDERECO_CIDADE",
                  "ENDERECO_UF", "ENDERECO_PAIS", "ENDERECO_CEP", "TELEFONE_PESSOA", "VALOR_RENDA",
                  "DATA_ATUALIZACAO_RENDA", "DATA_INICIO_RELACIONAMENTO", "DATA_FIM_RELACIONAMENTO"],
    "EXTRATO": ["CODIGO_CHAVE_EXTRATO", "NUMERO_BANCO", "NUMERO_AGENCIA", "NUMERO_CONTA", "TIPO_CONTA",
                "DATA_LANCAMENTO", "NUMERO_DOCUMENTO", "DESCRICAO_LANCAMENTO", "TIPO_LANCAMENTO",
                "VALOR_LANCAMENTO", "NATUREZA_LANCAMENTO", "VALOR_SALDO", "NATUREZA_SALDO", "LOCAL_TRANSACAO"],
    "ORIGEM_DESTINO": ["CODIGO_CHAVE_OD", "CODIGO_CHAVE_EXTRATO", "VALOR_TRANSACAO", "NUMERO_DOCUMENTO_TRANSACAO",
                       "NUMERO_BANCO_OD", "NUMERO_AGENCIA_OD", "NUMERO_CONTA_OD", "TIPO_CONTA_OD", "TIPO_PESSOA_OD",
                       "CPF_CNPJ_OD", "NOME_PESSOA_OD", "NOME_DOC_IDENTIFICACAO_OD", "NUMERO_DOC_IDENTIFICACAO_OD",
                       "CODIGO_DE_BARRAS", "NOME_ENDOSSANTE_CHEQUE", "DOC_ENDOSSANTE_CHEQUE",
                       "SITUACAO_IDENTIFICACAO", "OBSERVACAO"],
}

TIPOS_LANCAMENTO = {
    101: "cheques", 102: "encargos", 103: "estornos", 104: "lancamento avisado", 105: "tarifas", 106: "aplicacao",
    107: "emprestimo/financiamento", 108: "cambio", 109: "CPMF", 110: "IOF", 111: "imposto de renda",
    112: "pagamento fornecedores", 113: "pagamento salario", 114: "saque eletronico", 115: "acoes",
    117: "transferencia entre contas", 118: "devolucao da compensacao", 119: "devolucao de cheque depositado",
    120: "transf. interbancaria (DOC/TED)", 121: "antecipacao a fornecedores", 122: "OC/AEROPS",
    201: "depositos", 202: "liquido de cobranca", 203: "devolucao de cheques", 204: "estornos",
    205: "lancamento avisado", 206: "resgate de aplicacao", 207: "emprestimo/financiamento", 208: "cambio",
    209: "transf. interbancaria (DOC/TED)", 210: "acoes", 211: "dividendos", 212: "seguro",
    213: "transferencia entre contas", 214: "depositos especiais", 215: "devolucao da compensacao", 216: "OCT",
    217: "pagamento fornecedores", 218: "pagamentos diversos", 219: "pagamentos salariais",
}

# B2: créditos que não são renda, pelo código CNAB ou pela descrição (usada só aqui e descartada)
CREDITO_NAO_RENDA_COD = {203: "devolução", 204: "estorno", 206: "resgate de aplicação",
                         207: "empréstimo/financiamento", 215: "devolução"}
CREDITO_NAO_RENDA_TXT = [(r"RESGAT", "resgate de aplicação"), (r"ESTORN", "estorno"), (r"DEVOL", "devolução"),
                         (r"EMPREST|FINANC|CREDITO PESSOAL|CONSIGN", "empréstimo/financiamento")]


# ---------------------------------------------------------------- utilidades

def digitos(x: Optional[str]) -> str:
    return re.sub(r"\D", "", x or "")


def doc_norm(x: Optional[str], tipo: Optional[str] = None) -> Optional[str]:
    d = digitos(x)
    if not d or set(d) == {"0"}:
        return None
    t = (tipo or "").strip().upper()
    if t in ("1", "F", "PF"):
        return d.zfill(11)
    if t in ("2", "J", "PJ"):
        return d.zfill(14)
    return d.zfill(11) if len(d) <= 11 else d.zfill(14)


def eh_pf(doc: Optional[str]) -> bool:
    return bool(doc) and len(doc) == 11


def data_simba(s: Optional[str]) -> Optional[date]:
    d = digitos(s)
    if not d:
        return None
    try:
        return datetime.strptime(d.zfill(8), "%d%m%Y").date()
    except ValueError:
        return None


def data_iso(s: str) -> date:
    return datetime.strptime(s.strip(), "%Y-%m-%d").date()


def centavos_simba(s: Optional[str]) -> Optional[int]:
    d = (s or "").strip()
    if not re.fullmatch(r"-?\d+", d):
        return None
    return int(d)


def centavos_br(s: Optional[str]) -> Optional[int]:
    """'1.234,56' | '1234.56' | '1234' -> centavos (int)."""
    t = re.sub(r"[^\d,.\-]", "", s or "")
    if not t:
        return None
    if "," in t:
        t = t.replace(".", "").replace(",", ".")
    try:
        return int(round(float(t) * 100))
    except ValueError:
        return None


def brl(c: Optional[int]) -> str:
    """centavos -> '1234,56' (para CSV em Excel PT-BR)."""
    if c is None:
        return ""
    s = f"{abs(c) / 100:.2f}".replace(".", ",")
    return ("-" if c < 0 else "") + s


def brl_txt(c: Optional[int]) -> str:
    if c is None:
        return "-"
    s = f"{abs(c) / 100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    return ("-R$ " if c < 0 else "R$ ") + s


def chave_conta(banco, agencia, conta) -> str:
    return "|".join((digitos(banco).lstrip("0") or "0", digitos(agencia).lstrip("0") or "0",
                     digitos(conta).lstrip("0") or "0"))


def contas_equivalentes(a: str, b: str) -> bool:
    """mesmo banco e agência; conta igual, com ou sem o dígito verificador."""
    ba, ag, ca = a.split("|")
    bb, gb, cb = b.split("|")
    return ba == bb and ag == gb and (ca == cb or ca[:-1] == cb or cb[:-1] == ca)


def ler_csv(caminho: Path) -> List[Dict[str, str]]:
    if not caminho.is_file():
        return []
    with open(caminho, encoding="utf-8-sig", newline="") as f:
        linhas = [l for l in f if not l.lstrip().startswith("#")]
    leitor = csv.DictReader(linhas, delimiter=";")
    return [{k.strip(): (v or "").strip() for k, v in r.items() if k} for r in leitor
            if any((v or "").strip() for v in r.values())]


def escrever_csv(caminho: Path, colunas: List[str], linhas: Iterable[dict]):
    with open(caminho, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=colunas, delimiter=";", extrasaction="ignore")
        w.writeheader()
        for l in linhas:
            w.writerow(l)


# ---------------------------------------------------------------- pseudonimização (T1)

class Pseudonimizador:
    def __init__(self, segredo: bytes, titular: str):
        if len(segredo) < 32:
            raise ValueError("segredo curto demais (mínimo 32 bytes); gere com: gerar-segredo")
        self.segredo = segredo
        self.titular = titular
        self.vistos = set()

    def pf(self, cpf: str) -> str:
        h = hmac.new(self.segredo, cpf.encode(), hashlib.sha256).hexdigest()
        return "PF-" + h[:10].upper()

    def doc(self, doc: Optional[str]) -> Optional[str]:
        """titular e PJ ficam; PF de terceiro vira pseudônimo."""
        if not doc or doc == self.titular or not eh_pf(doc):
            return doc
        p = self.pf(doc)
        self.vistos.add(p)
        return p


def carregar_segredo(caminho: Path) -> bytes:
    bruto = caminho.read_bytes().strip()
    try:
        return bytes.fromhex(bruto.decode())
    except ValueError:
        return bruto


# ---------------------------------------------------------------- leitura SIMBA com pseudonimização

def _ler_txt(caminho: Path, colunas: List[str]) -> List[List[str]]:
    for enc in ("utf-8", "latin-1"):
        try:
            texto = caminho.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    linhas = [l.split("\t") for l in texto.splitlines() if l.strip()]
    if linhas and linhas[0][0].strip().upper() == colunas[0]:
        linhas = linhas[1:]
    n = len(colunas)
    return [[c.strip() for c in (l + [""] * n)[:n]] for l in linhas]


def _arquivos(pasta: Path, tipo: str) -> List[Path]:
    return sorted(p for p in pasta.rglob("*") if p.is_file() and p.suffix.lower() == ".txt"
                  and p.stem.upper().endswith(tipo))


def classificar_credito(cod: Optional[int], descricao: str) -> Optional[str]:
    if cod in CREDITO_NAO_RENDA_COD:
        return CREDITO_NAO_RENDA_COD[cod]
    d = (descricao or "").upper()
    for padrao, rot in CREDITO_NAO_RENDA_TXT:
        if re.search(padrao, d):
            return rot
    return None


def importar_simba(pasta: Path, ps: Pseudonimizador) -> dict:
    """lê os 5 arquivos e devolve só o que a análise precisa, já pseudonimizado.
    nenhum texto livre, nome de pessoa física, endereço ou telefone passa daqui."""
    contas, titulares, extrato, od = [], [], [], []
    arquivos = []
    for tipo in LEIAUTE:
        if tipo == "AGENCIAS":
            continue  # endereço e telefone de agência não são usados
        for arq in _arquivos(pasta, tipo):
            arquivos.append(arq.name)
            caso = arq.stem[: -len(tipo)].rstrip("_") or "-"
            cols = LEIAUTE[tipo]
            for vals in _ler_txt(arq, cols):
                r = dict(zip(cols, vals))
                if tipo == "CONTAS":
                    contas.append({"caso": caso, "conta": chave_conta(r["NUMERO_BANCO"], r["NUMERO_AGENCIA"], r["NUMERO_CONTA"]),
                                   "banco": digitos(r["NUMERO_BANCO"]).lstrip("0") or "0",
                                   "abertura": data_simba(r["DATA_ABERTURA_CONTA"]),
                                   "encerramento": data_simba(r["DATA_ENCERRAMENTO_CONTA"]),
                                   "movimentacao": r["MOVIMENTACAO_CONTA"]})
                elif tipo == "TITULARES":
                    doc = doc_norm(r["CPF_CNPJ_TITULAR"], r["TIPO_PESSOA_TITULAR"])
                    titulares.append({"caso": caso,
                                      "conta": chave_conta(r["NUMERO_BANCO"], r["NUMERO_AGENCIA"], r["NUMERO_CONTA"]),
                                      "tipo_titular": r["TIPO_TITULAR"], "investigado": r["PESSOA_INVESTIGADA"],
                                      "doc": ps.doc(doc),
                                      "nome": r["NOME_TITULAR"] if (doc == ps.titular or not eh_pf(doc)) else None})
                elif tipo == "EXTRATO":
                    cod = int(r["TIPO_LANCAMENTO"]) if r["TIPO_LANCAMENTO"].isdigit() else None
                    nat = r["NATUREZA_LANCAMENTO"].upper()
                    extrato.append({"caso": caso, "chave": r["CODIGO_CHAVE_EXTRATO"], "arquivo": arq.name,
                                    "conta": chave_conta(r["NUMERO_BANCO"], r["NUMERO_AGENCIA"], r["NUMERO_CONTA"]),
                                    "banco": digitos(r["NUMERO_BANCO"]).lstrip("0") or "0",
                                    "data": data_simba(r["DATA_LANCAMENTO"]), "data_bruta": r["DATA_LANCAMENTO"],
                                    "tipo": cod, "tipo_desc": TIPOS_LANCAMENTO.get(cod or -1, ""),
                                    "valor": centavos_simba(r["VALOR_LANCAMENTO"]), "natureza": nat,
                                    "saldo": centavos_simba(r["VALOR_SALDO"]), "natureza_saldo": r["NATUREZA_SALDO"].upper(),
                                    "nao_renda": classificar_credito(cod, r["DESCRICAO_LANCAMENTO"]) if nat == "C" else None})
                    # DESCRICAO_LANCAMENTO e LOCAL_TRANSACAO são descartados aqui
                elif tipo == "ORIGEM_DESTINO":
                    doc = doc_norm(r["CPF_CNPJ_OD"], r["TIPO_PESSOA_OD"])
                    proprio = doc is not None and doc == ps.titular
                    od.append({"caso": caso, "chave": r["CODIGO_CHAVE_EXTRATO"], "chave_od": r["CODIGO_CHAVE_OD"],
                               "valor": centavos_simba(r["VALOR_TRANSACAO"]),
                               "doc": ps.doc(doc), "pj": bool(doc) and not eh_pf(doc),
                               "nome_pj": r["NOME_PESSOA_OD"] if (doc and not eh_pf(doc)) else None,
                               "banco_od": digitos(r["NUMERO_BANCO_OD"]).lstrip("0") or None,
                               # conta de destino só é guardada quando é do próprio titular (C2)
                               "conta_od": chave_conta(r["NUMERO_BANCO_OD"], r["NUMERO_AGENCIA_OD"], r["NUMERO_CONTA_OD"])
                               if proprio and digitos(r["NUMERO_CONTA_OD"]) else None,
                               "proprio": proprio})
    return {"contas": contas, "titulares": titulares, "extrato": extrato, "od": od, "arquivos": arquivos}


# ---------------------------------------------------------------- 6.5 checagens SIMBA

def saldo_assinado(l: dict) -> Optional[int]:
    if l["saldo"] is None:
        return None
    return -l["saldo"] if l["natureza_saldo"] == "D" else l["saldo"]


def valor_assinado(l: dict) -> int:
    v = l["valor"] or 0
    return v if l["natureza"] == "C" else -v if l["natureza"] == "D" else 0


def ordenar_extrato(ext: List[dict]) -> Dict[Tuple[str, str], List[dict]]:
    por = defaultdict(list)
    for l in ext:
        por[(l["caso"], l["conta"])].append(l)
    for k in por:
        por[k].sort(key=lambda l: (l["data"] or date.min, int(l["chave"]) if l["chave"].isdigit() else 0))
    return por


def quebras_saldo(seq: List[dict], tol: int) -> List[Tuple[dict, dict, int]]:
    out = []
    for ant, atu in zip(seq, seq[1:]):
        s0, s1 = saldo_assinado(ant), saldo_assinado(atu)
        if s0 is None or s1 is None or atu["natureza"] not in ("C", "D"):
            continue
        dif = s1 - (s0 + valor_assinado(atu))
        if abs(dif) > tol:
            out.append((ant, atu, dif))
    return out


def quebra_por_ordem(seq: List[dict], ant: dict, atu: dict, tol: int) -> bool:
    """B4: a quebra some se os lançamentos do dia de `atu` forem reordenados? isto é, saldo do fim do dia
    anterior + soma do dia = saldo do último lançamento do dia. uma quebra causada por lançamento
    faltando em outro dia não fecha assim."""
    dia = [l for l in seq if l["data"] == atu["data"]]
    if len(dia) < 2:
        return False
    idx = seq.index(dia[0])
    s_ini = saldo_assinado(seq[idx - 1]) if idx > 0 else None
    if s_ini is None:
        return True
    s_fim = saldo_assinado(dia[-1])
    return s_fim is not None and abs(s_ini + sum(valor_assinado(l) for l in dia) - s_fim) <= tol


def checagens_simba(S: dict, tol: int) -> List[dict]:
    ext, od, contas = S["extrato"], S["od"], S["contas"]
    r = []

    def add(chk, sit, qtd, det):
        r.append({"checagem": chk, "situacao": sit, "qtd": qtd, "detalhe": det})

    if not ext:
        add("arquivos", "não avaliável", 0, "nenhum EXTRATO encontrado")
        return r
    chaves = defaultdict(int)
    for l in ext:
        chaves[(l["caso"], l["chave"])] += 1
    dup = sum(v - 1 for v in chaves.values() if v > 1)
    add("6.5 chave do extrato sem repetição", "ok" if not dup else "falha", dup, "CODIGO_CHAVE_EXTRATO repetido")
    k_ext = set(chaves)
    orf = sum((o["caso"], o["chave"]) not in k_ext for o in od)
    add("6.5 origem/destino ligado a lançamento", "ok" if not orf else "falha", orf, "ORIGEM_DESTINO sem lançamento")
    soma = defaultdict(int)
    tem = set()
    for o in od:
        if o["valor"] is not None:
            soma[(o["caso"], o["chave"])] += o["valor"]
            tem.add((o["caso"], o["chave"]))
    dif = sum(1 for l in ext if (l["caso"], l["chave"]) in tem and l["valor"] is not None
              and abs(soma[(l["caso"], l["chave"])] - l["valor"]) > tol)
    add("6.5 soma origem/destino = lançamento", "ok" if not dif else "falha", dif,
        "soma de VALOR_TRANSACAO diferente de VALOR_LANCAMENTO")
    k_od = {(o["caso"], o["chave"]) for o in od}
    sem_od = sum((l["caso"], l["chave"]) not in k_od for l in ext)
    add("6.5 lançamento com origem/destino", "ok" if not sem_od else "observação", sem_od,
        "lançamento sem registro em ORIGEM_DESTINO (o leiaute pede ao menos 1)")
    total_q, ordem = 0, 0
    for seq in ordenar_extrato(ext).values():
        for ant, atu, _ in quebras_saldo(seq, tol):
            if quebra_por_ordem(seq, ant, atu, tol):
                ordem += 1
            else:
                total_q += 1
    add("6.5 saldo fecha (B4 aplicada)", "ok" if not total_q else "falha", total_q,
        f"saldo anterior + lançamento ≠ saldo informado; {ordem} quebra(s) explicada(s) só pela ordem do dia (B4)")
    invalidas = sum(1 for l in ext if l["data"] is None)
    add("6.5 datas válidas", "ok" if not invalidas else "falha", invalidas, "DATA_LANCAMENTO fora do formato DDMMAAAA")
    contas_ext = {(l["caso"], l["conta"]) for l in ext}
    sem_mov = [c["conta"] for c in contas if c["movimentacao"] == "1" and (c["caso"], c["conta"]) not in contas_ext]
    add("6.5 conta com movimentação tem lançamentos", "ok" if not sem_mov else "falha", len(sem_mov),
        "MOVIMENTACAO_CONTA=1 sem lançamentos: " + (", ".join(sem_mov) or "-"))
    return r


# ---------------------------------------------------------------- 9 completude

def meses(ini: date, fim: date) -> List[Tuple[int, int]]:
    out, a, m = [], ini.year, ini.month
    while (a, m) <= (fim.year, fim.month):
        out.append((a, m))
        m += 1
        if m == 13:
            a, m = a + 1, 1
    return out


def no_escopo_banco(banco: str, escopo: dict) -> bool:
    inst = escopo.get("instituicoes", "todas")
    return inst == "todas" or banco.lstrip("0") in {str(i).lstrip("0") for i in inst}


def completude(S: dict, esc: dict, bens: List[dict], bases: List[dict], tol: int) -> List[dict]:
    ini, fim = data_iso(esc["periodo_inicio"]), data_iso(esc["periodo_fim"])
    r = []

    def add(teste, conjunto, item, sit, det):
        r.append({"teste": teste, "conjunto": conjunto, "item": item, "situacao": sit, "detalhe": det})

    entregues = {c["conta"] for c in S["contas"]} | {l["conta"] for l in S["extrato"]}
    por_conta = ordenar_extrato(S["extrato"])

    def entregue(conta: str) -> bool:
        return any(contas_equivalentes(conta, e) for e in entregues)

    # C1 contas declaradas no IR
    declaradas = set()
    for b in bens:
        if not digitos(b.get("conta")):
            continue
        k = chave_conta(b.get("banco"), b.get("agencia"), b.get("conta"))
        declaradas.add(k)
        ano = b.get("ano", "")
        rot = f"conta {k} (IR {ano}, {b.get('descricao', '')[:40]})"
        if not no_escopo_banco(k.split("|")[0], esc):
            add("C1 contas declaradas", "bancário", rot, "fora do escopo", "instituição fora da autorização (L1)")
        elif entregue(k):
            add("C1 contas declaradas", "bancário", rot, "ok", "extrato entregue")
        else:
            add("C1 contas declaradas", "bancário", rot, "lacuna",
                "conta declarada no IR, dentro do escopo, sem extrato entregue (verificar L2/L3)")
    if not declaradas:
        add("C1 contas declaradas", "bancário", "-", "não avaliável", "nenhuma conta informada em ir_bens.csv")

    # C2 contas do próprio titular referidas em transferências
    referidas = defaultdict(int)
    for o in S["od"]:
        if o["proprio"] and o["conta_od"]:
            referidas[o["conta_od"]] += 1
    for k, n in sorted(referidas.items()):
        if entregue(k):
            continue
        if not no_escopo_banco(k.split("|")[0], esc):
            add("C2 contas referidas", "bancário", f"conta {k}", "fora do escopo",
                f"{n} transferência(s) do/para o titular; instituição fora da autorização (L1)")
        else:
            add("C2 contas referidas", "bancário", f"conta {k}", "lacuna",
                f"{n} transferência(s) do/para o próprio titular envolvem esta conta, que não foi entregue")
    if not any(x["teste"].startswith("C2") for x in r):
        add("C2 contas referidas", "bancário", "-", "ok", "todas as contas próprias referidas foram entregues")

    # C3 cobertura de período e C4 continuidade, por conta entregue
    info_conta = {c["conta"]: c for c in S["contas"]}
    for (caso, k), seq in sorted(por_conta.items()):
        c = info_conta.get(k, {})
        a_ini = max(ini, c.get("abertura") or ini)
        a_fim = min(fim, c.get("encerramento") or fim)
        if a_ini > a_fim:
            add("C3 cobertura de período", "bancário", f"conta {k}", "fora do escopo", "conta fora do período autorizado")
            continue
        com_lanc = {(l["data"].year, l["data"].month) for l in seq if l["data"]}
        faltam = [f"{m:02d}/{a}" for a, m in meses(a_ini, a_fim) if (a, m) not in com_lanc]
        if faltam:
            add("C3 cobertura de período", "bancário", f"conta {k}", "verificar",
                f"{len(faltam)} mês(es) sem lançamento: {', '.join(faltam[:24])}{' …' if len(faltam) > 24 else ''}. "
                "Pode ser conta parada; ver C4 para saber se o saldo confirma.")
        else:
            add("C3 cobertura de período", "bancário", f"conta {k}", "ok",
                f"lançamentos em todos os meses de {a_ini:%m/%Y} a {a_fim:%m/%Y}")
        datas = [l["data"] for l in seq if l["data"]]
        if datas and (min(datas) - a_ini).days > 31:
            add("C3 cobertura de período", "bancário", f"conta {k}", "verificar",
                f"primeiro lançamento em {min(datas):%d/%m/%Y}, mais de 31 dias depois do início ({a_ini:%d/%m/%Y})")
        if datas and (a_fim - max(datas)).days > 31:
            add("C3 cobertura de período", "bancário", f"conta {k}", "verificar",
                f"último lançamento em {max(datas):%d/%m/%Y}, mais de 31 dias antes do fim ({a_fim:%d/%m/%Y})")
        quebras = [(a, b, d) for a, b, d in quebras_saldo(seq, tol) if not quebra_por_ordem(seq, a, b, tol)]
        if quebras:
            det = "; ".join(f"entre {a['data']:%d/%m/%Y} e {b['data']:%d/%m/%Y}: diferença de saldo de {brl_txt(d)} "
                            f"(indica {'débito' if d < 0 else 'crédito'} não listado)"
                            for a, b, d in quebras[:10] if a["data"] and b["data"])
            add("C4 continuidade de saldo", "bancário", f"conta {k}", "lacuna",
                f"{len(quebras)} quebra(s) de saldo não explicadas pela ordem do dia (B4): {det}. "
                "Indica lançamentos ou período faltando.")
        else:
            add("C4 continuidade de saldo", "bancário", f"conta {k}", "ok", "saldo contínuo em todo o extrato")

    # C5 bases fiscais
    autorizadas = esc.get("bases_fiscais", [])
    entregue_b = {(b.get("base", "").upper(), b.get("ano", "")) for b in bases
                  if b.get("entregue", "").strip().upper() in ("S", "SIM")}
    if not autorizadas:
        add("C5 bases fiscais", "fiscal", "-", "não avaliável", "escopo não informa bases fiscais autorizadas")
    for b in autorizadas:
        base = b["base"].upper()
        faltam = [str(a) for a in b.get("anos", []) if (base, str(a)) not in entregue_b]
        add("C5 bases fiscais", "fiscal", base, "lacuna" if faltam else "ok",
            f"anos autorizados sem entrega: {', '.join(faltam)}" if faltam else "entregue em todos os anos autorizados")

    # C6 coerência com o escopo
    bancos_aut = esc.get("instituicoes", "todas")
    if bancos_aut != "todas":
        bancos_entregues = {c["banco"] for c in S["contas"]} | {l["banco"] for l in S["extrato"]}
        for bco in bancos_aut:
            bco = str(bco).lstrip("0")
            add("C6 coerência com o escopo", "bancário", f"instituição {bco}",
                "ok" if bco in bancos_entregues else "lacuna",
                "dados entregues" if bco in bancos_entregues else
                "instituição autorizada sem nenhum dado entregue (verificar se é falha da instituição: L3)")
        fora = sorted(b for b in bancos_entregues if b not in {str(x).lstrip("0") for x in bancos_aut})
        if fora:
            add("C6 coerência com o escopo", "bancário", "instituições fora da autorização", "verificar",
                f"dados entregues de instituições não listadas no escopo: {', '.join(fora)}")
    datas = [l["data"] for l in S["extrato"] if l["data"]]
    if datas:
        fora = sum(1 for d in datas if d < ini or d > fim)
        add("C6 coerência com o escopo", "bancário", "período dos lançamentos",
            "ok" if not fora else "verificar",
            f"lançamentos de {min(datas):%d/%m/%Y} a {max(datas):%d/%m/%Y}; {fora} fora do período autorizado")
    return r


def escala_completude(linhas: List[dict], conjunto: str) -> str:
    sel = [l for l in linhas if l["conjunto"] == conjunto]
    if not sel or all(l["situacao"] == "não avaliável" for l in sel):
        return "Não avaliável"
    if any(l["situacao"] == "lacuna" for l in sel):
        return "Lacunas encontradas (explicação a verificar: L2/L3)"
    if any(l["situacao"] == "verificar" for l in sel):
        return "Sem lacunas confirmadas; há itens a verificar"
    return "Sem lacunas (candidato a Completo)"


# ---------------------------------------------------------------- 7.3 cruzamento bancário × fiscal

def movimentos(S: dict) -> List[dict]:
    """um registro por lançamento, com a contraparte (se houver uma só) e as classificações B1, B2, B5."""
    od_por = defaultdict(list)
    for o in S["od"]:
        od_por[(o["caso"], o["chave"])].append(o)
    out = []
    for l in S["extrato"]:
        ods = od_por.get((l["caso"], l["chave"]), [])
        # vários registros de origem/destino: divide pelo VALOR_TRANSACAO só se todos tiverem valor;
        # senão usa o lançamento uma vez só, com a primeira contraparte (evita contar em dobro)
        dividir = len(ods) > 1 and all(o["valor"] is not None for o in ods)
        partes = ods if dividir else ods[:1] or [None]
        for o in partes:
            valor = (o["valor"] if dividir else l["valor"]) or 0
            proprio = bool(o and o["proprio"])
            classe = ("conta própria (B1)" if proprio else
                      f"não é renda (B2: {l['nao_renda']})" if l["nao_renda"] else
                      "saque em espécie" if l["tipo"] == 114 else
                      "contraparte não identificada (B5)" if not (o and o["doc"]) else
                      "contraparte identificada")
            out.append({"caso": l["caso"], "conta": l["conta"], "data": l["data"], "ano": l["data"].year if l["data"] else None,
                        "natureza": l["natureza"], "valor": valor, "tipo": l["tipo"], "tipo_desc": l["tipo_desc"],
                        "contraparte": (o["doc"] if o else None), "contraparte_pj": bool(o and o["pj"]),
                        "nome_pj": (o["nome_pj"] if o else None), "classe": classe})
    return out


def saldo_em(seq: List[dict], dia: date) -> Optional[int]:
    antes = [l for l in seq if l["data"] and l["data"] <= dia and saldo_assinado(l) is not None]
    return saldo_assinado(antes[-1]) if antes else None


def cruzamentos(S: dict, mov: List[dict], bens, rends, dividas, tol: int, ps: Pseudonimizador) -> List[dict]:
    r = []
    por_conta = ordenar_extrato(S["extrato"])

    def add(tipo, ano, item, fiscal, bancario, obs, criterio=""):
        dif = None if fiscal is None or bancario is None else fiscal - bancario
        r.append({"tipo": tipo, "ano": ano, "item": item, "valor_fiscal": fiscal, "valor_bancario": bancario,
                  "diferenca": dif, "dentro_tolerancia": "" if dif is None else ("sim" if abs(dif) <= tol else "não"),
                  "criterio": criterio, "observacao": obs})

    # saldo em 31/12
    for b in bens:
        if not digitos(b.get("conta")) or not b.get("ano"):
            continue
        k = chave_conta(b.get("banco"), b.get("agencia"), b.get("conta"))
        ano = int(b["ano"])
        seq = next((s for (c, kk), s in por_conta.items() if contas_equivalentes(k, kk)), None)
        fiscal = centavos_br(b.get("saldo_31_12"))
        if seq is None:
            add("Saldo em 31/12", ano, f"conta {k}", fiscal, None, "conta sem extrato (ver C1)")
            continue
        banc = saldo_em(seq, date(ano, 12, 31))
        add("Saldo em 31/12", ano, f"conta {k}", fiscal, banc,
            "sem lançamento até 31/12 no extrato" if banc is None else "saldo do último lançamento até 31/12")

    # rendimentos por fonte pagadora
    cred = defaultdict(int)
    for m in mov:
        if m["natureza"] == "C" and m["contraparte"] and m["ano"]:
            cred[(m["contraparte"], m["ano"])] += m["valor"]
    for x in rends:
        fonte = doc_norm(x.get("cnpj_cpf_fonte"))
        if not fonte or not x.get("ano"):
            continue
        ano = int(x["ano"])
        bruto = centavos_br(x.get("valor")) or 0
        liquido = bruto - (centavos_br(x.get("imposto_retido")) or 0) - (centavos_br(x.get("previdencia")) or 0)
        chave = ps.doc(fonte)
        rot = chave if not eh_pf(fonte) else f"{chave} (fonte PF)"
        nome = x.get("nome_fonte", "")[:40] if not eh_pf(fonte) else ""
        add("Rendimentos × créditos da fonte", ano, f"{rot} {nome}".strip(), liquido, cred.get((chave, ano), 0),
            "valor fiscal = bruto − IR retido − previdência; consignações, pensão e adiantamentos explicam diferenças",
            "bruto × líquido: conferir descontos não informados")

    # dívidas: pagamentos ao credor
    deb = defaultdict(int)
    for m in mov:
        if m["natureza"] == "D" and m["contraparte"] and m["ano"]:
            deb[(m["contraparte"], m["ano"])] += m["valor"]
    for d in dividas:
        credor = doc_norm(d.get("credor_cnpj"))
        if not credor or not d.get("ano") or not d.get("valor_pago_no_ano"):
            continue
        ano = int(d["ano"])
        chave = ps.doc(credor)
        add("Pagamentos de dívida declarada", ano, f"{chave} {d.get('descricao', '')[:40]}".strip(),
            centavos_br(d.get("valor_pago_no_ano")), deb.get((chave, ano), 0),
            "débitos ao credor no ano; débito automático sem contraparte identificada não entra (B5)")

    # B3: créditos líquidos × rendimentos líquidos declarados (bruto − IR retido − previdência), por ano
    total_rend = defaultdict(int)
    for x in rends:
        if x.get("ano"):
            total_rend[int(x["ano"])] += ((centavos_br(x.get("valor")) or 0) - (centavos_br(x.get("imposto_retido")) or 0)
                                          - (centavos_br(x.get("previdencia")) or 0))
    liq = defaultdict(int)
    for m in mov:
        if m["natureza"] == "C" and m["ano"] and m["classe"] not in ("conta própria (B1)",) and not m["classe"].startswith("não é renda"):
            liq[m["ano"]] += m["valor"]
    for ano in sorted(set(total_rend) | set(liq)):
        if ano not in total_rend:
            continue
        add("Créditos líquidos × rendimentos (B3)", ano, "total do ano", total_rend[ano], liq.get(ano, 0),
            "diferença a explicar (B3); créditos já sem contas próprias (B1) e sem não-renda (B2). "
            "Não é 'renda omitida'. Valor fiscal = rendimentos − IR retido − previdência.",
            "rendimentos líquidos × créditos")
    return r


# ---------------------------------------------------------------- agregados (T2)

def agregados(mov: List[dict]) -> List[dict]:
    por = defaultdict(lambda: defaultdict(int))
    contr = defaultdict(lambda: defaultdict(set))
    for m in mov:
        if not m["ano"]:
            continue
        a, nat = m["ano"], m["natureza"]
        lado = "creditos" if nat == "C" else "debitos" if nat == "D" else None
        if not lado:
            continue
        por[a][f"{lado}_brutos"] += m["valor"]
        chave = {"conta própria (B1)": "contas_proprias", "saque em espécie": "especie",
                 "contraparte não identificada (B5)": "nao_identificado"}.get(m["classe"])
        if m["classe"].startswith("não é renda"):
            chave = "nao_renda"
        if chave:
            por[a][f"{lado}_{chave}"] += m["valor"]
        if m["contraparte"] and not m["classe"].startswith("conta própria"):
            tipo = "pj" if m["contraparte_pj"] else "pf"
            contr[a][f"{lado}_{tipo}"].add(m["contraparte"])
            por[a][f"{lado}_valor_{tipo}"] += m["valor"]
    out = []
    for a in sorted(por):
        p, c = por[a], contr[a]
        out.append({"ano": a,
                    "creditos_brutos": brl(p["creditos_brutos"]),
                    "creditos_contas_proprias_B1": brl(p["creditos_contas_proprias"]),
                    "creditos_nao_renda_B2": brl(p["creditos_nao_renda"]),
                    "creditos_liquidos": brl(p["creditos_brutos"] - p["creditos_contas_proprias"] - p["creditos_nao_renda"]),
                    "creditos_nao_identificados_B5": brl(p["creditos_nao_identificado"]),
                    "creditos_de_pf_valor": brl(p["creditos_valor_pf"]), "creditos_de_pf_qtd_pessoas": len(c["creditos_pf"]),
                    "creditos_de_pj_valor": brl(p["creditos_valor_pj"]), "creditos_de_pj_qtd_empresas": len(c["creditos_pj"]),
                    "debitos_brutos": brl(p["debitos_brutos"]),
                    "debitos_contas_proprias_B1": brl(p["debitos_contas_proprias"]),
                    "saques_em_especie": brl(p["debitos_especie"]),
                    "debitos_nao_identificados_B5": brl(p["debitos_nao_identificado"]),
                    "debitos_para_pf_valor": brl(p["debitos_valor_pf"]), "debitos_para_pf_qtd_pessoas": len(c["debitos_pf"]),
                    "debitos_para_pj_valor": brl(p["debitos_valor_pj"]), "debitos_para_pj_qtd_empresas": len(c["debitos_pj"])})
    return out


# ---------------------------------------------------------------- comandos

ESCOPO_MODELO = {
    "_leia": "Transcreva o que o titular autorizou, com a folha dos autos. instituicoes: lista de códigos COMPE "
             "(ex.: [\"1\", \"104\"]) ou \"todas\". Datas no formato AAAA-MM-DD. Apague as linhas _leia e _exemplo.",
    "_exemplo": "EXEMPLO FICTÍCIO: substitua todos os valores",
    "referencia_autos": "Processo 0000000-00.0000.0.00.0000, fls. 000",
    "periodo_inicio": "2019-01-01",
    "periodo_fim": "2024-12-31",
    "instituicoes": "todas",
    "bases_fiscais": [{"base": "DIRPF", "anos": [2019, 2020, 2021, 2022, 2023, 2024]},
                      {"base": "DIRF", "anos": [2019, 2020, 2021, 2022, 2023, 2024]}],
}

MODELOS = {
    "ir_bens.csv": ("# Bens e direitos com conta bancária, transcritos da DIRPF de cada ano. Valores em R$ (1.234,56). "
                    "Uma linha por conta por ano. Apague a linha de exemplo.",
                    ["ano", "codigo_bem", "descricao", "banco", "agencia", "conta", "saldo_31_12_anterior", "saldo_31_12",
                     "fonte_autos"],
                    ["2023", "61", "EXEMPLO FICTICIO conta corrente", "104", "1000", "123456", "5.000,00", "7.500,00",
                     "fls. 000"]),
    "ir_rendimentos.csv": ("# Rendimentos por fonte pagadora, transcritos da DIRPF. tipo: tributavel, isento ou exclusivo. "
                           "Apague a linha de exemplo.",
                           ["ano", "tipo", "cnpj_cpf_fonte", "nome_fonte", "valor", "imposto_retido", "previdencia",
                            "fonte_autos"],
                           ["2023", "tributavel", "11.222.333/0001-81", "EXEMPLO FICTICIO LTDA", "120.000,00",
                            "25.000,00", "10.000,00", "fls. 000"]),
    "ir_dividas.csv": ("# Dívidas e ônus reais, transcritos da DIRPF. Apague a linha de exemplo.",
                       ["ano", "descricao", "credor_cnpj", "situacao_31_12_anterior", "situacao_31_12",
                        "valor_pago_no_ano", "fonte_autos"],
                       ["2023", "EXEMPLO FICTICIO financiamento", "11.222.333/0001-81", "300.000,00", "280.000,00",
                        "36.000,00", "fls. 000"]),
    "bases_entregues.csv": ("# O que efetivamente foi entregue nos autos, por base e ano. entregue: S ou N. "
                            "Apague a linha de exemplo.",
                            ["base", "ano", "entregue", "fonte_autos"],
                            ["DIRPF", "2023", "S", "fls. 000"]),
}


def cmd_gerar_segredo(a):
    p = Path(a.arquivo)
    if p.exists():
        print(f"{p} já existe; não sobrescrevo (trocar o segredo muda todos os pseudônimos)", file=sys.stderr)
        return 1
    p.write_text(secrets.token_hex(32) + "\n")
    try:
        p.chmod(0o600)
    except OSError:
        pass
    print(f"segredo gravado em {p}. Guarde com a Custódia, fora do ambiente dos analistas.")
    return 0


def cmd_modelos(a):
    pasta = Path(a.pasta)
    pasta.mkdir(parents=True, exist_ok=True)
    escopo = pasta / "escopo.json"
    if not escopo.exists():
        escopo.write_text(json.dumps(ESCOPO_MODELO, ensure_ascii=False, indent=2), encoding="utf-8")
    for nome, (aviso, cols, exemplo) in MODELOS.items():
        p = pasta / nome
        if p.exists():
            continue
        with open(p, "w", encoding="utf-8-sig", newline="") as f:
            f.write(aviso + "\n")
            w = csv.writer(f, delimiter=";")
            w.writerow(cols)
            w.writerow(exemplo)
    print(f"modelos em {pasta}/ (arquivos existentes não foram alterados)")
    return 0


def cmd_pseudonimo(a):
    ps = Pseudonimizador(carregar_segredo(Path(a.segredo)), "")
    cpf = doc_norm(a.cpf, "F")
    print(ps.pf(cpf) if cpf else "CPF inválido")
    return 0


def cmd_analisar(a):
    titular = doc_norm(a.titular_cpf, "F")
    if not titular:
        print("CPF do titular inválido", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[A-Za-z0-9._-]+", a.id):
        print("o --id só pode ter letras, números, ponto, hífen e sublinhado", file=sys.stderr)
        return 1
    ent = Path(a.entradas)
    try:
        esc = json.loads((ent / "escopo.json").read_text(encoding="utf-8"))
        esc["periodo_inicio"], esc["periodo_fim"]
    except (OSError, ValueError, KeyError) as e:
        print(f"escopo.json ausente ou inválido em {ent}: {e}", file=sys.stderr)
        return 1
    if "_exemplo" in esc:
        print("[aviso] escopo.json ainda tem a linha _exemplo: confira se os valores foram substituídos", file=sys.stderr)
    tol = centavos_br(a.tolerancia)
    ps = Pseudonimizador(carregar_segredo(Path(a.segredo)), titular)
    bens, rends = ler_csv(ent / "ir_bens.csv"), ler_csv(ent / "ir_rendimentos.csv")
    dividas, bases = ler_csv(ent / "ir_dividas.csv"), ler_csv(ent / "bases_entregues.csv")
    exemplos = [n for n, rows in (("ir_bens", bens), ("ir_rendimentos", rends), ("ir_dividas", dividas))
                if any("EXEMPLO" in " ".join(r.values()).upper() for r in rows)]
    if exemplos:
        print(f"[aviso] linha de EXEMPLO ainda presente em: {', '.join(exemplos)}", file=sys.stderr)

    S = importar_simba(Path(a.simba), ps) if a.simba else {"contas": [], "titulares": [], "extrato": [], "od": [], "arquivos": []}
    saida = Path(a.saida) / a.id
    saida.mkdir(parents=True, exist_ok=True)

    chk = checagens_simba(S, tol)
    comp = completude(S, esc, bens, bases, tol)
    mov = movimentos(S)
    cruz = cruzamentos(S, mov, bens, rends, dividas, tol, ps)
    agr = agregados(mov)

    escrever_csv(saida / "checagens_simba.csv", ["checagem", "situacao", "qtd", "detalhe"], chk)
    escrever_csv(saida / "completude.csv", ["teste", "conjunto", "item", "situacao", "detalhe"], comp)
    escrever_csv(saida / "cruzamentos.csv",
                 ["tipo", "ano", "item", "valor_fiscal", "valor_bancario", "diferenca", "dentro_tolerancia", "criterio", "observacao"],
                 [{**c, "valor_fiscal": brl(c["valor_fiscal"]), "valor_bancario": brl(c["valor_bancario"]),
                   "diferenca": brl(c["diferenca"])} for c in cruz])
    escrever_csv(saida / "agregados_publicaveis.csv", list(agr[0].keys()) if agr else ["ano"], agr)
    escrever_csv(saida / "movimentos_pseudonimizados.csv",
                 ["caso", "conta", "data", "natureza", "valor", "tipo", "tipo_desc", "contraparte", "contraparte_pj",
                  "nome_pj", "classe"],
                 [{**m, "data": m["data"].strftime("%d/%m/%Y") if m["data"] else "", "valor": brl(m["valor"]),
                   "contraparte_pj": "sim" if m["contraparte_pj"] else ""} for m in mov])

    # candidatas para a aba Divergencias (colunas A–E, H–L da planilha)
    cand = []
    for i, c in enumerate(x for x in cruz if x["dentro_tolerancia"] == "não"):
        cand.append({"ID": f"{a.id}-D{i + 1:03d}", "ID item": a.id, "Campo / item analisado": f"{c['tipo']} {c['ano']}: {c['item']}",
                     "Valor no documento (R$)": brl(c["valor_fiscal"]), "Valor na fonte (R$)": brl(c["valor_bancario"]),
                     "Fonte primária": "extrato SIMBA nos autos", "URL / referência": "", "Data da consulta": "",
                     "Diferença de critério?": "", "Explicação possível": c["observacao"]})
    escrever_csv(saida / "divergencias_candidatas.csv",
                 ["ID", "ID item", "Campo / item analisado", "Valor no documento (R$)", "Valor na fonte (R$)",
                  "Fonte primária", "URL / referência", "Data da consulta", "Diferença de critério?", "Explicação possível"], cand)
    lac = [x for x in comp if x["situacao"] == "lacuna"]
    escrever_csv(saida / "lacunas_candidatas.csv", ["teste", "conjunto", "item", "situacao", "detalhe"], lac)

    meta = {"id": a.id, "data_execucao_utc": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            "script": f"modulo_f5.py v{VERSAO}",
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "tolerancia": brl_txt(tol), "arquivos_simba": S["arquivos"],
            "arquivos_simba_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in sorted(Path(a.simba).rglob("*")) if p.is_file() and p.suffix.lower() == ".txt"}
            if a.simba else {},
            "entradas_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(ent.iterdir()) if p.is_file()},
            "pseudonimos_distintos": len(ps.vistos)}
    (saida / "execucao.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    md = [f"# Relatório F5: {a.id}", "",
          "> Observações automáticas. Lacunas e divergências aqui são **candidatas**: passam pela revisão cega, pelo "
          "Red Team e pelo Comitê (protocolo v2.0, seções 9, 13 e 14) antes de qualquer conclusão.", "",
          f"- Script: `modulo_f5.py v{VERSAO}` (SHA-256 `{meta['script_sha256']}`)",
          f"- Execução (UTC): {meta['data_execucao_utc']}",
          f"- Escopo: {esc['periodo_inicio']} a {esc['periodo_fim']}; instituições: {esc.get('instituicoes')}; "
          f"referência: {esc.get('referencia_autos', '-')}",
          f"- Tolerância (V1): {meta['tolerancia']}",
          f"- Arquivos SIMBA: {len(S['arquivos'])}; lançamentos: {len(S['extrato'])}; origens/destinos: {len(S['od'])}; "
          f"contrapartes PF pseudonimizadas: {len(ps.vistos)}", "",
          "## Completude (P4)", "", "| Conjunto | Resultado automático |", "|---|---|"]
    for conj in ("bancário", "fiscal"):
        md.append(f"| {conj} | {escala_completude(comp, conj)} |")
    md += ["", "| Teste | Item | Situação | Detalhe |", "|---|---|---|---|"]
    md += [f"| {x['teste']} | {x['item']} | **{x['situacao']}** | {x['detalhe']} |" for x in comp]
    md += ["", "## Integridade dos arquivos SIMBA (6.5)", "", "| Checagem | Situação | Qtd | Detalhe |", "|---|---|---|---|"]
    md += [f"| {x['checagem']} | **{x['situacao']}** | {x['qtd']} | {x['detalhe']} |" for x in chk]
    md += ["", "## Cruzamento bancário × fiscal (7.3)", "",
           "| Tipo | Ano | Item | Fiscal | Bancário | Diferença | Dentro da tolerância |", "|---|---|---|---|---|---|---|"]
    md += [f"| {c['tipo']} | {c['ano']} | {c['item']} | {brl_txt(c['valor_fiscal'])} | {brl_txt(c['valor_bancario'])} | "
           f"{brl_txt(c['diferenca'])} | {c['dentro_tolerancia'] or '-'} |" for c in cruz]
    md += ["", "Não automatizado: aquisição e alienação de bens × contrapartida financeira (7.3, última linha). "
               "Fazer à mão, a partir de movimentos_pseudonimizados.csv.", "",
           "## Arquivos gerados", "",
           "| Arquivo | Uso | Pode publicar? |", "|---|---|---|",
           "| relatorio_f5.md | este resumo | após revisão |",
           "| completude.csv / lacunas_candidatas.csv | P4 | após revisão |",
           "| cruzamentos.csv / divergencias_candidatas.csv | P3; colar na aba Divergencias | após revisão |",
           "| checagens_simba.csv | 6.5 | sim |",
           "| agregados_publicaveis.csv | T2: só totais e contagens | sim |",
           "| movimentos_pseudonimizados.csv | trabalho interno | **não** (T2) |",
           "| execucao.json | hashes de entradas e do script, para reproduzir | sim |", ""]
    (saida / "relatorio_f5.md").write_text("\n".join(md), encoding="utf-8")

    print(f"{len(S['extrato'])} lançamentos, {len(ps.vistos)} contrapartes PF pseudonimizadas")
    print(f"completude: bancário = {escala_completude(comp, 'bancário')}; fiscal = {escala_completude(comp, 'fiscal')}")
    print(f"{len(lac)} lacuna(s) candidata(s); {len(cand)} divergência(s) candidata(s)")
    print(f"saída em {saida}/")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Módulo F5: completude e cruzamento bancário × fiscal (protocolo v2.0).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gerar-segredo", help="cria o segredo da pseudonimização (Custódia)")
    g.add_argument("--arquivo", required=True)
    m = sub.add_parser("modelos", help="cria os modelos de entrada")
    m.add_argument("--pasta", required=True)
    p = sub.add_parser("pseudonimo", help="mostra o pseudônimo de um CPF (Custódia, procedimento T3)")
    p.add_argument("--segredo", required=True)
    p.add_argument("--cpf", required=True)
    an = sub.add_parser("analisar", help="roda completude e cruzamentos")
    an.add_argument("--simba", help="pasta com os .txt do SIMBA")
    an.add_argument("--entradas", required=True, help="pasta com escopo.json e os CSVs do IR")
    an.add_argument("--titular-cpf", required=True)
    an.add_argument("--segredo", required=True)
    an.add_argument("--id", required=True, help="ID do conjunto, ex.: CONJ-01")
    an.add_argument("--tolerancia", default="1,00", help="tolerância V1 em R$ (padrão 1,00)")
    an.add_argument("--saida", default="f5")
    a = ap.parse_args(argv)
    return {"gerar-segredo": cmd_gerar_segredo, "modelos": cmd_modelos, "pseudonimo": cmd_pseudonimo,
            "analisar": cmd_analisar}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
