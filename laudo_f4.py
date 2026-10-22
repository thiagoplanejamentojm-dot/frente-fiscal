#!/usr/bin/env python3
"""Laudo técnico F4: perícia de integridade de um PDF (protocolo v2.0, seções 6.1 a 6.3).

uso:
    python3 laudo_f4.py COPIA.pdf --id DOC-001 --executor M01 --hash-esperado <sha256 da custódia>
    python3 laudo_f4.py COPIA.pdf --id DOC-001 --executor M01 --hash-esperado ... --referencia REF.pdf

o que faz:
    - confere o hash da cópia de trabalho com o da custódia (se não bater, para)
    - lê o PDF como bytes, sem executar nada dele, e registra: revisões (atualizações
      incrementais), o que cada atualização acrescentou ou substituiu, metadados Info e XMP,
      datas, fontes, imagens, assinatura digital, elementos ativos
    - com --referencia, compara com um PDF gerado pelo programa oficial do mesmo ano (6.2)
    - se exiftool, qpdf e poppler (pdffonts, pdfimages, pdftotext, pdfinfo) estiverem
      instalados, roda também e guarda as saídas brutas
    - grava em SAIDA/<ID>/: laudo_<ID>.md, laudo_<ID>.json, log_testes_<ID>.csv (pronto para
      colar na aba Log_Testes), brutos/ e revisoes/ (cada versão anterior do arquivo)

o script só registra observações. ele nunca conclui "adulterado": pelas regras G1 a G4 do protocolo,
quem decide é o Comitê, depois da revisão cega e do Red Team. o único "Não conforme"
automático é o hash da cópia diferente do hash da custódia.

só usa a biblioteca padrão do Python (3.9+). rode sempre sobre uma cópia, nunca sobre o original."""
import argparse
import csv
import difflib
import hashlib
import json
import re
import shutil
import subprocess
import sys
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

VERSAO = "1.2"
LIMITE_STREAM = 50 * 1024 * 1024  # não descomprime além disso (proteção contra zip bomb)
MAX_STREAMS = 20000

CONFORME, OBSERVACAO, NAO_CONFORME, INCONCLUSIVO, NAO_APLICAVEL = (
    "Conforme", "Observação", "Não conforme", "Inconclusivo", "Não aplicável")


# ----------------------------------------------------------------- leitura do PDF

def calcular_hashes(caminho: Path) -> Tuple[str, str]:
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h256.update(bloco)
            h512.update(bloco)
    return h256.hexdigest(), h512.hexdigest()


def descomprimir(dados: bytes) -> Optional[bytes]:
    try:
        d = zlib.decompressobj()
        return d.decompress(dados, LIMITE_STREAM)
    except zlib.error:
        return None


RE_OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.S)
RE_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\n?endstream", re.S)


def objetos(dados: bytes) -> List[dict]:
    """objetos indiretos do trecho: número, dicionário e conteúdo do stream (descomprimido se possível)."""
    lista = []
    for m in RE_OBJ.finditer(dados):
        corpo = m.group(3)
        s = RE_STREAM.search(corpo)
        dic = corpo[: s.start()] if s else corpo
        conteudo = None
        if s and len(lista) < MAX_STREAMS:
            bruto = s.group(1)
            conteudo = descomprimir(bruto) if b"/FlateDecode" in dic else bruto
        lista.append({"num": int(m.group(1)), "dic": dic, "stream": conteudo})
        # objetos dentro de object streams (PDF 1.5+)
        if conteudo and b"/ObjStm" in dic:
            lista.append({"num": -1, "dic": conteudo, "stream": None, "em_objstm": True})
    return lista


def tipo_objeto(o: dict) -> str:
    dic = o["dic"]
    t = re.search(rb"/Type\s*/(\w+)", dic)
    st = re.search(rb"/Subtype\s*/(\w+)", dic)
    if t and st:
        return f"{t.group(1).decode()}/{st.group(1).decode()}"
    if t:
        return t.group(1).decode()
    if st:
        return st.group(1).decode()
    if b"/Producer" in dic or b"/CreationDate" in dic or b"/ModDate" in dic:
        return "Info (metadados)"
    if o["stream"] is not None and re.search(rb"\bBT\b", o["stream"]) and re.search(rb"T[Jj]\b", o["stream"]):
        return "Conteúdo de página (com texto)"
    if o["stream"] is not None:
        return "Stream"
    return "Outro"


def desescapar_pdf(b: bytes) -> str:
    out, i = bytearray(), 0
    mapa = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12,
            ord("("): 40, ord(")"): 41, ord("\\"): 92}
    while i < len(b):
        c = b[i]
        if c == 92 and i + 1 < len(b):
            n = b[i + 1]
            if n in mapa:
                out.append(mapa[n]); i += 2; continue
            m = re.match(rb"[0-7]{1,3}", b[i + 1:i + 4])
            if m:
                out.append(int(m.group(0), 8) & 0xFF); i += 1 + len(m.group(0)); continue
            if n in (10, 13):
                i += 2; continue
            i += 1; continue
        out.append(c); i += 1
    return decodificar_texto(bytes(out))


def decodificar_texto(b: bytes) -> str:
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", "replace")
    if b.startswith(b"\xef\xbb\xbf"):
        return b[3:].decode("utf-8", "replace")
    return b.decode("latin-1")


def ler_literal(b: bytes, i: int) -> Tuple[Optional[bytes], int]:
    """lê uma string literal PDF que começa em b[i] == '(' (aceita parênteses aninhados).
    devolve (conteúdo bruto, posição depois do ')')."""
    if i >= len(b) or b[i] != 40:
        return None, i
    prof, j, ini = 1, i + 1, i + 1
    while j < len(b):
        c = b[j]
        if c == 92:
            j += 2
            continue
        if c == 40:
            prof += 1
        elif c == 41:
            prof -= 1
            if prof == 0:
                return b[ini:j], j + 1
        j += 1
    return None, len(b)


def campo_info(blob: bytes, chave: str) -> List[str]:
    vals = []
    k = chave.encode()
    for m in re.finditer(rb"/" + k + rb"\s*(?=\()", blob):
        bruto, _ = ler_literal(blob, m.end())
        if bruto is not None:
            vals.append(desescapar_pdf(bruto))
    for m in re.finditer(rb"/" + k + rb"\s*<([0-9A-Fa-f\s]*)>", blob):
        try:
            vals.append(decodificar_texto(bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode())))
        except ValueError:
            pass
    return vals


def campo_xmp(blob: bytes, tag: str) -> List[str]:
    t = tag.encode()
    vals = [m.group(1).decode("utf-8", "replace").strip()
            for m in re.finditer(rb"<" + t + rb">\s*(.*?)\s*</" + t + rb">", blob, re.S)]
    vals += [m.group(1).decode("utf-8", "replace").strip()
             for m in re.finditer(t + rb'="([^"]*)"', blob)]
    # pode vir dentro de rdf:Alt/rdf:li
    return [re.sub(r"<[^>]+>", "", v).strip() for v in vals if v]


def data_pdf(s: str) -> Optional[datetime]:
    m = re.match(r"D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+\-])?(\d{2})?'?(\d{2})?'?", s.strip())
    if not m:
        return None
    a, mo, d, h, mi, se, sinal, th, tm = m.groups()
    try:
        base = datetime(int(a), int(mo or 1), int(d or 1), int(h or 0), int(mi or 0), int(se or 0))
    except ValueError:
        return None
    if sinal in ("+", "-"):
        delta = timedelta(hours=int(th or 0), minutes=int(tm or 0))
        return base.replace(tzinfo=timezone(delta if sinal == "+" else -delta))
    return base.replace(tzinfo=timezone.utc) if sinal in ("Z", "z") else base


def data_iso(s: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def comparavel(d: datetime) -> datetime:
    """datas sem fuso são tratadas como UTC só para comparação (anotado no laudo)."""
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def textos_desenhados(stream: bytes) -> List[str]:
    """texto aproximado dos operadores Tj/TJ (pode vir ilegível com fontes CID)."""
    out, pend, i, n = [], [], 0, len(stream)
    while i < n:
        c = stream[i]
        if c == 40:  # (
            bruto, i = ler_literal(stream, i)
            if bruto is not None:
                pend.append(desescapar_pdf(bruto))
            continue
        if stream.startswith(b"Tj", i) or stream.startswith(b"TJ", i) or stream.startswith(b"'", i):
            if pend:
                out.append("".join(pend))
            pend = []
        elif c in b"\r\n\t []-0123456789.":
            pass
        elif chr(c).isalpha() and not stream.startswith(b"Tf", i):
            pend = []  # outro operador: descarta strings sem Tj/TJ
        i += 1
    return [t for t in (x.strip() for x in out) if t]


class Analise:
    """tudo o que se extrai do PDF sem ferramentas externas."""

    def __init__(self, caminho: Path):
        self.caminho = caminho
        self.dados = caminho.read_bytes()
        d = self.dados
        cab = re.match(rb"\s*%PDF-(\d\.\d)", d[:1024])
        self.versao_pdf = cab.group(1).decode() if cab else None
        self.linearizado = b"/Linearized" in d[:2048]
        fins = [m.end() for m in re.finditer(rb"%%EOF[ \t]*(\r\n|\r|\n)?", d)]
        if self.linearizado and len(fins) > 1:
            fins = fins[1:]  # o 1º %%EOF de um PDF linearizado não é revisão
        self.fins_revisao = fins or [len(d)]
        self.lixo_final = len(d) - self.fins_revisao[-1]
        self.objs = objetos(d)
        blobs = [d] + [o["stream"] for o in self.objs if o["stream"]] + \
                [o["dic"] for o in self.objs if o.get("em_objstm")]
        self.blobs = blobs
        tudo = b"\n".join(blobs)
        # estado atual: para cada número de objeto vale a última definição (atualizações substituem)
        atuais: Dict[int, dict] = {}
        soltos = []
        for o in self.objs:
            if o["num"] >= 0:
                atuais[o["num"]] = o
            else:
                soltos.append(o)
        atual = b"\n".join([o["dic"] for o in list(atuais.values()) + soltos])
        self.producer = sorted(set(sum((campo_info(b, "Producer") for b in blobs), [])))
        self.creator = sorted(set(sum((campo_info(b, "Creator") for b in blobs), [])))
        self.criacao = sorted(set(sum((campo_info(b, "CreationDate") for b in blobs), [])))
        self.modificacao = sorted(set(sum((campo_info(b, "ModDate") for b in blobs), [])))
        self.xmp_producer = sorted(set(campo_xmp(tudo, "pdf:Producer")))
        self.xmp_creator = sorted(set(campo_xmp(tudo, "xmp:CreatorTool")))
        self.xmp_criacao = sorted(set(campo_xmp(tudo, "xmp:CreateDate")))
        self.xmp_modificacao = sorted(set(campo_xmp(tudo, "xmp:ModifyDate")))
        self.fontes = sorted(set(re.sub(r"^[A-Z]{6}\+", "", m.group(1).decode("latin-1"))
                                 for m in re.finditer(rb"/BaseFont\s*/([^\s/\[\]<>()]+)", atual)))
        self.n_paginas = len(re.findall(rb"/Type\s*/Page(?![a-zA-Z])", atual))
        self.n_imagens = len(re.findall(rb"/Subtype\s*/Image\b", atual))
        m = re.search(rb"/MediaBox\s*\[\s*([\d.\-\s]+)\]", atual)
        self.mediabox = " ".join(m.group(1).decode().split()) if m else None
        self.byteranges = [[int(x) for x in m.group(1).split()]
                           for m in re.finditer(rb"/ByteRange\s*\[\s*([\d\s]+)\]", d)]
        self.ativos = {k: len(re.findall(p, tudo)) for k, p in {
            "JavaScript": rb"/(JavaScript|JS)\b", "OpenAction": rb"/OpenAction\b", "Launch": rb"/Launch\b",
            "EmbeddedFile": rb"/EmbeddedFile\b", "SubmitForm": rb"/SubmitForm\b"}.items()}

    def segmentos(self) -> List[Tuple[int, int]]:
        inicio, segs = 0, []
        for fim in self.fins_revisao:
            segs.append((inicio, fim))
            inicio = fim
        return segs

    def revisoes_extras(self) -> int:
        return len(self.fins_revisao) - 1


# ------------------------------------------------------------ ferramentas externas

FERRAMENTAS = {
    "exiftool": (["exiftool", "-ver"], lambda a: ["exiftool", "-a", "-G1", "-s", a]),
    "qpdf": (["qpdf", "--version"], lambda a: ["qpdf", "--check", a]),
    "pdffonts": (["pdffonts", "-v"], lambda a: ["pdffonts", a]),
    "pdfimages": (["pdfimages", "-v"], lambda a: ["pdfimages", "-list", a]),
    "pdfinfo": (["pdfinfo", "-v"], lambda a: ["pdfinfo", a]),
}


def rodar(cmd: List[str], timeout: int = 180) -> Tuple[Optional[int], str]:
    if not shutil.which(cmd[0]):
        return None, ""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return -1, "(tempo esgotado)"
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", "replace")


def versao_ferramenta(nome: str) -> Optional[str]:
    rc, out = rodar(FERRAMENTAS[nome][0], 30)
    if rc is None:
        return None
    return (out.strip().splitlines() or ["?"])[0]


def texto_paginas(arquivo: Path) -> Optional[List[str]]:
    if not (shutil.which("pdftotext") and shutil.which("pdfinfo")):
        return None
    rc, info = rodar(["pdfinfo", str(arquivo)])
    m = re.search(r"Pages:\s+(\d+)", info or "")
    if not m:
        return None
    paginas = []
    for p in range(1, int(m.group(1)) + 1):
        _, t = rodar(["pdftotext", "-layout", "-f", str(p), "-l", str(p), str(arquivo), "-"])
        paginas.append(t)
    return paginas


# ------------------------------------------------------------------------- testes

class Laudo:
    def __init__(self, id_item: str, executor: str, saida: Path):
        self.id_item, self.executor, self.saida = id_item, executor, saida
        self.testes: List[dict] = []
        (saida / "brutos").mkdir(parents=True, exist_ok=True)

    def bruto(self, nome: str, conteudo: str) -> str:
        p = self.saida / "brutos" / nome
        p.write_text(conteudo, encoding="utf-8")
        return f"brutos/{nome}"

    def add(self, fase, teste, comando, resultado, observacao, alternativa="", bruto=""):
        self.testes.append({
            "id": f"{self.id_item}-T{len(self.testes) + 1:02d}", "fase": fase, "teste": teste,
            "comando": comando, "resultado": resultado, "observacao": observacao,
            "alternativa": alternativa, "bruto": bruto})


F41, F42, F43 = "F4.1 Criptográfica", "F4.2 Referência", "F4.3 Estrutural"
PROPRIO = f"laudo_f4.py v{VERSAO} (Python, leitura de bytes)"


def teste_estrutura(L: Laudo, A: Analise):
    if A.versao_pdf:
        L.add(F43, "Cabeçalho PDF", PROPRIO, CONFORME, f"Cabeçalho %PDF-{A.versao_pdf}.")
    else:
        L.add(F43, "Cabeçalho PDF", PROPRIO, OBSERVACAO,
              "Cabeçalho %PDF não encontrado no início do arquivo.",
              "Arquivo pode não ser PDF ou ter bytes antes do cabeçalho (alguns geradores fazem isso).")
    if A.lixo_final > 2:
        L.add(F43, "Bytes após o último %%EOF", PROPRIO, OBSERVACAO,
              f"{A.lixo_final} bytes depois do último marcador %%EOF.",
              "Alguns servidores e programas acrescentam bytes de preenchimento; verificar o conteúdo.")


def teste_revisoes(L: Laudo, A: Analise):
    n = A.revisoes_extras()
    pasta = L.saida / "revisoes"
    det = []
    if n == 0:
        L.add(F43, "Atualizações incrementais", PROPRIO, CONFORME,
              "Uma única revisão: nenhuma atualização incremental depois da geração."
              + (" (arquivo linearizado; o 1º %%EOF foi desconsiderado)" if A.linearizado else ""))
        return
    pasta.mkdir(exist_ok=True)
    vistos = set()
    segs = A.segmentos()
    for i, (ini, fim) in enumerate(segs):
        (pasta / f"revisao_{i + 1}.pdf").write_bytes(A.dados[:fim])
        objs = objetos(A.dados[ini:fim])
        nums = {o["num"] for o in objs if o["num"] >= 0}
        if i == 0:
            vistos |= nums
            continue
        subst = sorted(nums & vistos)
        novos = sorted(nums - vistos)
        vistos |= nums
        tipos: Dict[str, int] = {}
        textos = []
        for o in objs:
            t = tipo_objeto(o)
            tipos[t] = tipos.get(t, 0) + 1
            if o["stream"]:
                textos += textos_desenhados(o["stream"])
        # conteúdo de página novo ou imagem nova é o sinal forte; Page substituída sozinha costuma ser
        # só a lista de anotações (assinatura, comentário), e XObject/Form costuma ser aparência de assinatura
        visivel = any(t in ("Conteúdo de página (com texto)", "XObject/Image") for t in tipos)
        assinatura = any(t.startswith(("Sig", "Annot/Widget")) for t in tipos) or b"/ByteRange" in A.dados[ini:fim]
        det.append({"revisao": i + 1, "bytes": fim - ini, "substituidos": subst, "novos": novos,
                    "tipos": tipos, "texto": textos[:40], "conteudo_visivel": visivel, "assinatura": assinatura})
    rel = []
    for r in det:
        rel.append(f"Revisão {r['revisao']}{' (contém assinatura)' if r['assinatura'] else ''}: {r['bytes']} bytes; "
                   f"objetos substituídos {r['substituidos'] or '-'}; "
                   f"novos {r['novos'] or '-'}; tipos {r['tipos']}"
                   + (f"; texto desenhado (aproximado): {r['texto']}" if r["texto"] else ""))
    bruto = L.bruto("revisoes.json", json.dumps(det, ensure_ascii=False, indent=2))
    algum_visivel = any(r["conteudo_visivel"] for r in det)
    obs = (f"{n} atualização(ões) incremental(is) depois da geração. Cada versão anterior foi salva em revisoes/. "
           + ("Pelo menos uma atualização ACRESCENTA OU SUBSTITUI CONTEÚDO DE PÁGINA COM TEXTO OU IMAGEM: "
              "candidato a indício pela regra G3, exige comparação visual das revisões e revisão cega. "
              if algum_visivel else
              "As atualizações parecem tocar só metadados, anotações, formulário ou assinatura. ")
           + " | ".join(rel))
    L.add(F43, "Atualizações incrementais", PROPRIO, OBSERVACAO, obs,
          "Assinar, preencher formulário, anotar ou salvar num leitor de PDF cria revisões sem mudar o "
          "conteúdo original; comparar visualmente revisao_N.pdf com a final.", bruto)


def teste_metadados(L: Laudo, A: Analise):
    prods = sorted(set(A.producer + A.xmp_producer))
    crs = sorted(set(A.creator + A.xmp_creator))
    txt = f"Producer (Info): {A.producer or '-'}; Creator (Info): {A.creator or '-'}; " \
          f"Producer (XMP): {A.xmp_producer or '-'}; CreatorTool (XMP): {A.xmp_creator or '-'}"
    if not prods and not crs:
        L.add(F43, "Produtor e criador", PROPRIO, OBSERVACAO,
              "Nenhum produtor ou criador registrado: perda de rastreabilidade (regra G1). " + txt,
              "Compressores, sites e 'salvar como' removem metadados.")
    elif len(prods) > 1 or len(crs) > 1:
        L.add(F43, "Produtor e criador", PROPRIO, OBSERVACAO,
              "Mais de um produtor/criador no arquivo: ele passou por mais de um programa. " + txt,
              "Reexportação ou assinatura por outro software (regra G2); comparar com as revisões.")
    else:
        L.add(F43, "Produtor e criador", PROPRIO, CONFORME, "Produtor/criador únicos. " + txt)

    criacoes = [d for d in (data_pdf(s) for s in A.criacao) if d] + \
               [d for d in (data_iso(s) for s in A.xmp_criacao) if d]
    mods = [d for d in (data_pdf(s) for s in A.modificacao) if d] + \
           [d for d in (data_iso(s) for s in A.xmp_modificacao) if d]
    txt = f"CreationDate: {A.criacao or '-'}; ModDate: {A.modificacao or '-'}; " \
          f"XMP CreateDate: {A.xmp_criacao or '-'}; XMP ModifyDate: {A.xmp_modificacao or '-'}"
    if not criacoes and not mods:
        L.add(F43, "Datas de criação e modificação", PROPRIO, OBSERVACAO,
              "Sem datas registradas: perda de rastreabilidade (regra G1). " + txt,
              "Metadados removidos por compressão ou reexportação.")
        return
    alertas = []
    if criacoes and mods:
        c, m = min(map(comparavel, criacoes)), max(map(comparavel, mods))
        if m < c:
            alertas.append("modificação ANTERIOR à criação")
        elif m - c > timedelta(minutes=1):
            dif = m - c
            alertas.append(f"modificação {dif.days} dia(s) e {dif.seconds // 3600} hora(s) depois da criação"
                           if dif.days else f"modificação {dif.seconds // 60} minuto(s) depois da criação")
    if len(set(map(comparavel, criacoes))) > 1:
        alertas.append("mais de uma data de criação distinta")
    if alertas:
        L.add(F43, "Datas de criação e modificação", PROPRIO, OBSERVACAO,
              "; ".join(alertas).capitalize() + ". " + txt,
              "Assinatura, reexportação ou salvar novamente atualizam a data de modificação; "
              "datas sem fuso foram comparadas como UTC.")
    else:
        L.add(F43, "Datas de criação e modificação", PROPRIO, CONFORME,
              "Criação e modificação coincidem (diferença de até 1 minuto). " + txt)


def teste_fontes_imagens(L: Laudo, A: Analise):
    sub = "Fontes embutidas ou referenciadas: " + (", ".join(A.fontes) if A.fontes else "nenhuma")
    if A.n_paginas and not A.fontes:
        L.add(F43, "Fontes", PROPRIO, OBSERVACAO, sub + ". Documento sem fontes: o conteúdo pode ser só imagem.",
              "Documento digitalizado ou impresso como imagem.")
    else:
        L.add(F43, "Fontes", PROPRIO, CONFORME, sub + ". Comparar com a referência (6.2) e checar homogeneidade.")
    L.add(F43, "Páginas e imagens", PROPRIO, CONFORME if A.n_imagens == 0 else OBSERVACAO,
          f"{A.n_paginas} página(s); {A.n_imagens} imagem(ns); MediaBox {A.mediabox or '-'}."
          + (" Verificar se alguma imagem cobre trecho que deveria ser texto (regra G3)." if A.n_imagens else ""),
          "Logotipos, brasões e códigos de barras são imagens legítimas." if A.n_imagens else "")


def teste_assinatura(L: Laudo, A: Analise):
    if not A.byteranges:
        L.add(F41, "Assinatura digital", PROPRIO, NAO_APLICAVEL,
              "Nenhuma assinatura digital (/ByteRange) no arquivo: a verificação criptográfica não se aplica.")
        return
    tam = len(A.dados)
    partes = []
    cobre_tudo = False
    for br in A.byteranges:
        if len(br) == 4:
            fim = br[2] + br[3]
            partes.append(f"ByteRange {br}: cobre até o byte {fim} de {tam}")
            cobre_tudo = cobre_tudo or fim == tam
    obs = (f"{len(A.byteranges)} assinatura(s). " + "; ".join(partes) + ". "
           + ("A última assinatura cobre o arquivo inteiro. " if cobre_tudo else
              "NENHUMA assinatura cobre o arquivo inteiro: houve acréscimo depois da última assinatura. ")
           + "Este script NÃO valida a assinatura: validar em validar.iti.gov.br e anexar o relatório (6.1).")
    L.add(F41, "Assinatura digital (abrangência)", PROPRIO, OBSERVACAO, obs,
          "Acréscimos após assinar podem ser legítimos (carimbo do tempo, dados de validação LTV, nova assinatura)."
          if not cobre_tudo else "")


def teste_ativos(L: Laudo, A: Analise):
    achados = {k: v for k, v in A.ativos.items() if v}
    if achados:
        L.add(F43, "Elementos ativos", PROPRIO, OBSERVACAO,
              f"Elementos ativos encontrados: {achados}. Abrir o arquivo só em ambiente isolado.",
              "Formulários e anexos podem ser legítimos; não indicam por si alteração de conteúdo.")
    else:
        L.add(F43, "Elementos ativos", PROPRIO, CONFORME, "Sem JavaScript, ações automáticas, anexos ou envio de formulário.")


def testes_externos(L: Laudo, arquivo: Path, A: Analise):
    a = str(arquivo)
    for nome, teste in (("exiftool", "Metadados (exiftool)"), ("qpdf", "Integridade estrutural (qpdf --check)"),
                        ("pdffonts", "Fontes (pdffonts)"), ("pdfimages", "Imagens (pdfimages -list)")):
        cmd = FERRAMENTAS[nome][1](a)
        rc, out = rodar(cmd)
        if rc is None:
            L.add(F43, teste, " ".join(cmd), INCONCLUSIVO, f"{nome} não instalado nesta máquina; teste não executado.")
            continue
        bruto = L.bruto(f"{nome}.txt", out)
        if nome == "qpdf":
            ok = "No syntax or stream encoding errors" in out
            L.add(F43, teste, " ".join(cmd), CONFORME if ok else OBSERVACAO,
                  "Sem erros de sintaxe ou codificação." if ok else "qpdf relatou avisos ou erros; ver saída bruta.",
                  "" if ok else "Geradores antigos produzem PDFs com pequenos erros de estrutura.", bruto)
        else:
            L.add(F43, teste, " ".join(cmd), CONFORME, "Saída registrada para revisão e comparação com a referência.",
                  "", bruto)

    paginas = texto_paginas(arquivo)
    if paginas is None:
        L.add(F43, "Camada de texto por página", "pdfinfo + pdftotext -layout", INCONCLUSIVO,
              "poppler (pdftotext/pdfinfo) não instalado; teste não executado.")
    else:
        sem_texto = [i + 1 for i, t in enumerate(paginas) if len(re.sub(r"\s", "", t)) < 20]
        bruto = L.bruto("texto_paginas.txt", "\n\f".join(paginas))
        L.add(F43, "Camada de texto por página", "pdfinfo + pdftotext -layout",
              OBSERVACAO if sem_texto else CONFORME,
              f"Páginas sem camada de texto: {sem_texto}." if sem_texto else "Todas as páginas têm camada de texto.",
              "Página digitalizada ou impressa como imagem." if sem_texto else "", bruto)
        if A.revisoes_extras() and shutil.which("pdftotext"):
            difs, trechos = [], []
            final = "\n".join(paginas)
            linhas_final = [l.strip() for l in final.splitlines() if l.strip()]
            for i in range(1, A.revisoes_extras() + 1):
                rev = L.saida / "revisoes" / f"revisao_{i}.pdf"
                _, t = rodar(["pdftotext", "-layout", str(rev), "-"])
                if t.strip() != final.strip():
                    difs.append(i)
                    linhas_rev = [l.strip() for l in t.splitlines() if l.strip()]
                    sai = [l for l in linhas_rev if l not in linhas_final][:5]
                    entra = [l for l in linhas_final if l not in linhas_rev][:5]
                    trechos.append(f"revisão {i} → final: saiu {sai or '-'}; entrou {entra or '-'}")
            if difs:
                bruto_dif = L.bruto("texto_revisoes_diff.txt", "\n".join(
                    "".join(difflib.unified_diff(
                        rodar(["pdftotext", "-layout", str(L.saida / "revisoes" / f"revisao_{i}.pdf"), "-"])[1].splitlines(True),
                        final.splitlines(True), f"revisao_{i}.pdf", "versao_final")) for i in difs))
            L.add(F43, "Texto das revisões × versão final", "pdftotext -layout revisoes/revisao_N.pdf",
                  OBSERVACAO if difs else CONFORME,
                  f"Texto extraído difere da versão final nas revisões {difs}: candidato a indício (regra G3). "
                  + " | ".join(trechos) if difs else "O texto extraído é igual em todas as revisões.",
                  "Diferenças de extração podem vir de anotações ou campos de formulário." if difs else "",
                  bruto_dif if difs else "")


def comparar_referencia(L: Laudo, A: Analise, R: Analise):
    def comp(teste, va, vr, alternativa):
        igual = va == vr
        L.add(F42, teste, f"{PROPRIO} --referencia", CONFORME if igual else OBSERVACAO,
              f"Analisado: {va or '-'}; referência: {vr or '-'}.", "" if igual else alternativa)

    comp("Versão do PDF × referência", A.versao_pdf, R.versao_pdf,
         "Versão diferente do programa ou caminho de geração diferente.")
    comp("Produtor × referência", sorted(set(A.producer + A.xmp_producer)), sorted(set(R.producer + R.xmp_producer)),
         "Versão diferente do programa, reexportação ou impressão por outro caminho (regra G2).")
    comp("Criador × referência", sorted(set(A.creator + A.xmp_creator)), sorted(set(R.creator + R.xmp_creator)),
         "Versão diferente do programa ou impressão por outro caminho.")
    comp("Tamanho de página × referência", A.mediabox, R.mediabox, "Impressão em outro papel ou escala.")
    comp("Número de revisões × referência", A.revisoes_extras() + 1, R.revisoes_extras() + 1,
         "Assinatura ou salvamento posterior.")
    fa, fr = set(A.fontes), set(R.fontes)
    so_a, so_r = sorted(fa - fr), sorted(fr - fa)
    L.add(F42, "Fontes × referência", f"{PROPRIO} --referencia", CONFORME if not so_a else OBSERVACAO,
          f"Fontes só no analisado: {so_a or '-'}; só na referência: {so_r or '-'}; em comum: {sorted(fa & fr) or '-'}.",
          "" if not so_a else "Fontes extras podem vir de anotações, carimbos ou reexportação; "
                              "verificar em que trecho elas são usadas.")


# ------------------------------------------------------------------------- saída

COLS_LOG = ["ID teste", "ID item", "Fase", "Teste", "Ferramenta / comando", "Executor (codinome)", "Data",
            "Resultado", "Arquivo com saída bruta", "Observação", "Explicação alternativa considerada"]


def escrever(L: Laudo, meta: dict):
    base = f"laudo_{L.id_item}"
    a, m, d = meta["data_execucao"][:10].split("-")
    data = f"{d}/{m}/{a}"
    with open(L.saida / f"log_testes_{L.id_item}.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(COLS_LOG)
        for t in L.testes:
            w.writerow([t["id"], L.id_item, t["fase"], t["teste"], t["comando"], L.executor, data,
                        t["resultado"], t["bruto"], t["observacao"], t["alternativa"]])
    (L.saida / f"{base}.json").write_text(json.dumps({**meta, "testes": L.testes}, ensure_ascii=False, indent=2),
                                          encoding="utf-8")
    cont: Dict[str, int] = {}
    for t in L.testes:
        cont[t["resultado"]] = cont.get(t["resultado"], 0) + 1
    md = [f"# Laudo técnico F4: {L.id_item}", "",
          "> Este laudo registra **observações**, não conclusões. O veredito é do Comitê de Método, depois da "
          "revisão cega e do Red Team (protocolo v2.0, seções 8 e 12 a 14).", "",
          "## Identificação", "", "| Campo | Valor |", "|---|---|"]
    for k, rot in [("arquivo", "Arquivo analisado"), ("tamanho_bytes", "Tamanho (bytes)"), ("sha256", "SHA-256"),
                   ("sha512", "SHA-512"), ("hash_esperado", "SHA-256 da custódia"), ("referencia", "Referência (6.2)"),
                   ("referencia_sha256", "SHA-256 da referência"), ("executor", "Executor"),
                   ("data_execucao", "Data da execução (UTC)"), ("script", "Script"), ("script_sha256", "SHA-256 do script"),
                   ("python", "Python")]:
        md.append(f"| {rot} | `{meta.get(k) or '-'}` |")
    md += ["", "**Ferramentas externas:** " + "; ".join(f"{k}: {v or 'não instalado'}"
                                                    for k, v in meta["ferramentas"].items()), "",
           "## Resumo", "", "| Resultado | Quantidade |", "|---|---|"]
    md += [f"| {k} | {v} |" for k, v in cont.items()]
    md += ["", "| ID | Fase | Teste | Resultado |", "|---|---|---|---|"]
    md += [f"| {t['id']} | {t['fase']} | {t['teste']} | **{t['resultado']}** |" for t in L.testes]
    md += ["", "## Detalhes", ""]
    for t in L.testes:
        md += [f"### {t['id']}: {t['teste']}", "",
               f"- **Fase:** {t['fase']}", f"- **Comando:** `{t['comando']}`", f"- **Resultado:** {t['resultado']}",
               f"- **Observação:** {t['observacao']}"]
        if t["alternativa"]:
            md.append(f"- **Explicação alternativa a considerar:** {t['alternativa']}")
        if t["bruto"]:
            md.append(f"- **Saída bruta:** `{t['bruto']}`")
        md.append("")
    md += ["## Como reproduzir", "",
           "1. Baixe o arquivo pela URL registrada na custódia e confira o SHA-256 acima.",
           "2. Confira o SHA-256 do script acima.",
           f"3. Rode: `python3 laudo_f4.py ARQUIVO.pdf --id {L.id_item} --executor SEU_CODINOME"
           f" --hash-esperado {meta['sha256']}`" + (" --referencia REFERENCIA.pdf" if meta.get("referencia") else ""),
           "4. Os resultados devem coincidir; diferenças só são esperadas nos testes de ferramentas externas "
           "que não estejam instaladas.", ""]
    (L.saida / f"{base}.md").write_text("\n".join(md), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Laudo técnico F4 de um PDF (protocolo v2.0, seções 6.1 a 6.3).")
    ap.add_argument("arquivo", help="cópia de trabalho do PDF (nunca o original)")
    ap.add_argument("--id", required=True, help="ID do item na custódia, ex.: DOC-001")
    ap.add_argument("--executor", required=True, help="codinome de quem executa")
    ap.add_argument("--hash-esperado", help="SHA-256 registrado na custódia")
    ap.add_argument("--referencia", help="PDF gerado no programa oficial do mesmo ano, com dados fictícios (6.2)")
    ap.add_argument("--saida", default="laudos", help="pasta de saída (padrão: laudos)")
    a = ap.parse_args(argv)

    arq = Path(a.arquivo)
    if not arq.is_file():
        print(f"arquivo não encontrado: {arq}", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[A-Za-z0-9._-]+", a.id):
        print("o --id só pode ter letras, números, ponto, hífen e sublinhado", file=sys.stderr)
        return 1
    saida = Path(a.saida) / a.id
    saida.mkdir(parents=True, exist_ok=True)
    L = Laudo(a.id, a.executor, saida)

    sha256, sha512 = calcular_hashes(arq)
    meta = {"id_item": a.id, "arquivo": arq.name, "tamanho_bytes": arq.stat().st_size, "sha256": sha256,
            "sha512": sha512, "hash_esperado": a.hash_esperado, "executor": a.executor,
            "data_execucao": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "script": f"laudo_f4.py v{VERSAO}", "script_sha256": calcular_hashes(Path(__file__))[0],
            "python": sys.version.split()[0],
            "ferramentas": {n: versao_ferramenta(n) for n in FERRAMENTAS}}
    rc_t, out_t = rodar(["pdftotext", "-v"], 30)
    meta["ferramentas"]["pdftotext"] = (out_t.strip().splitlines() or ["?"])[0] if rc_t is not None else None

    if a.hash_esperado:
        if a.hash_esperado.strip().lower() != sha256:
            L.add(F43, "Hash da cópia × custódia", "sha256", NAO_CONFORME,
                  f"SHA-256 da cópia ({sha256}) difere do registrado na custódia ({a.hash_esperado}). "
                  "Análise interrompida: obtenha uma cópia íntegra (protocolo v2.0, seção 5.2).")
            escrever(L, meta)
            print(f"HASH NÃO CONFERE. análise interrompida. laudo em {saida}/", file=sys.stderr)
            return 2
        L.add(F43, "Hash da cópia × custódia", "sha256", CONFORME, "SHA-256 da cópia igual ao da custódia.")
    else:
        L.add(F43, "Hash da cópia × custódia", "sha256", INCONCLUSIVO,
              "Hash da custódia não informado (--hash-esperado): não foi possível confirmar que esta é a cópia íntegra.")

    A = Analise(arq)
    teste_estrutura(L, A)
    teste_revisoes(L, A)
    teste_metadados(L, A)
    teste_fontes_imagens(L, A)
    teste_assinatura(L, A)
    teste_ativos(L, A)
    testes_externos(L, arq, A)
    if a.referencia:
        ref = Path(a.referencia)
        meta["referencia"] = ref.name
        meta["referencia_sha256"] = calcular_hashes(ref)[0]
        comparar_referencia(L, A, Analise(ref))
    else:
        L.add(F42, "Comparação com referência", "--referencia", INCONCLUSIVO,
              "Nenhum PDF de referência informado: a comparação 6.2 não foi feita.")

    escrever(L, meta)
    cont: Dict[str, int] = {}
    for t in L.testes:
        cont[t["resultado"]] = cont.get(t["resultado"], 0) + 1
    print(f"{len(L.testes)} testes: " + ", ".join(f"{v} {k}" for k, v in cont.items()))
    print(f"laudo em {saida}/laudo_{a.id}.md  |  linhas para a planilha: {saida}/log_testes_{a.id}.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())
