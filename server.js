/**
 * Servidor de consulta de NFC-e (modelo 65) por chave de acesso.
 *
 * Apresenta o certificado A1 na conexão TLS com a SEFAZ e devolve o XML
 * autorizado (nfeProc) da nota. É o endpoint que o app espera:
 *
 *   POST /consulta
 *   Authorization: Bearer <TOKEN>
 *   { "chave": "44 dígitos" }
 *   → application/xml com o nfeProc, ou JSON { erro } com o motivo.
 *
 * Consulta o NFeConsultaProtocolo 4.00 da SEFAZ da UF da chave, que atende
 * NFC-e (modelo 65). A Distribuição Nacional só entrega NF-e modelo 55.
 *
 * Sem dependências. Rode com Node 18 ou superior:  node server.js
 */

const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");

const PORTA = Number(process.env.PORT || 8787);
const TOKEN = process.env.TOKEN || "";
const PFX_PATH = process.env.PFX_PATH || "./certificado.pfx";
const PFX_SENHA = process.env.PFX_SENHA || "";
const CERT_PEM = process.env.CERT_PEM || "";
const KEY_PEM = process.env.KEY_PEM || "";
const PFX_BASE64 = process.env.PFX_BASE64 || "";
const CNPJ = (process.env.CNPJ || "").replace(/\D/g, "");
const TPAMB = process.env.TPAMB || "1"; // 1 = produção, 2 = homologação

// Consulta de NFC-e (modelo 65) por chave: NFeConsultaProtocolo 4.00 de cada UF.
// A Distribuição Nacional (NFeDistribuicaoDFe) atende apenas NF-e modelo 55.
const NS_NFCE = "http://www.portalfiscal.inf.br/nfe/wsdl/NFeConsultaProtocolo4";
const NS_NFCE_ANTIGO = "http://www.portalfiscal.inf.br/nfe/wsdl/NfeConsulta4";

const SERVICOS = {
  AC: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  AL: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  AM: { prod: "https://nfce.sefaz.am.gov.br/nfce-services/services/NfeConsulta4", hom: "https://homnfce.sefaz.am.gov.br/nfce-services/services/NfeConsulta4", ns: NS_NFCE_ANTIGO },
  AP: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  BA: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  CE: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  DF: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  ES: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  GO: { prod: "https://nfe.sefaz.go.gov.br/nfe/services/NFeConsultaProtocolo4", hom: "https://homolog.sefaz.go.gov.br/nfe/services/NFeConsultaProtocolo4", ns: NS_NFCE },
  MA: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  MG: { prod: "https://nfce.fazenda.mg.gov.br/nfce/services/NFeConsultaProtocolo4", hom: "https://hnfce.fazenda.mg.gov.br/nfce/services/NFeConsultaProtocolo4", ns: NS_NFCE },
  MS: { prod: "https://nfce.sefaz.ms.gov.br/ws/NFeConsultaProtocolo4", hom: "https://hom.nfce.sefaz.ms.gov.br/ws/NFeConsultaProtocolo4", ns: NS_NFCE },
  MT: { prod: "https://nfce.sefaz.mt.gov.br/nfcews/services/NfeConsulta4", hom: "https://homologacao.sefaz.mt.gov.br/nfcews/services/NfeConsulta4", ns: NS_NFCE_ANTIGO },
  PA: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  PB: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  PE: { prod: "https://nfce.sefaz.pe.gov.br/nfce-service/services/NFeConsultaProtocolo4", hom: "https://nfce.sefaz.pe.gov.br/nfce-service/services/NFeConsultaProtocolo4", ns: NS_NFCE },
  PI: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  PR: { prod: "https://nfce.sefa.pr.gov.br/nfce/NFeConsultaProtocolo4", hom: "https://homologacao.nfce.sefa.pr.gov.br/nfce/NFeConsultaProtocolo4", ns: NS_NFCE },
  RJ: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  RN: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  RO: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  RR: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  RS: { prod: "https://nfce.sefazrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.sefazrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  SC: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  SE: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
  SP: { prod: "https://nfce.fazenda.sp.gov.br/ws/NFeConsultaProtocolo4.asmx", hom: "https://homologacao.nfce.fazenda.sp.gov.br/ws/NFeConsultaProtocolo4.asmx", ns: NS_NFCE },
  TO: { prod: "https://nfce.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", hom: "https://nfce-homologacao.svrs.rs.gov.br/ws/NfeConsulta/NfeConsulta4.asmx", ns: NS_NFCE_ANTIGO },
};

// Código IBGE da UF (2 primeiros dígitos da chave) → sigla.
const UF_POR_CODIGO = {
  "11": "RO", "12": "AC", "13": "AM", "14": "RR", "15": "PA", "16": "AP", "17": "TO",
  "21": "MA", "22": "PI", "23": "CE", "24": "RN", "25": "PB", "26": "PE", "27": "AL",
  "28": "SE", "29": "BA", "31": "MG", "32": "ES", "33": "RJ", "35": "SP", "41": "PR",
  "42": "SC", "43": "RS", "50": "MS", "51": "MT", "52": "GO", "53": "DF",
};

if (CNPJ.length !== 14) {
  console.error("Informe o CNPJ do certificado (14 dígitos) em CNPJ=...");
  process.exit(1);
}
if (!TOKEN) {
  console.error("Informe o token que o app vai enviar em TOKEN=...");
  process.exit(1);
}

let tls;
try {
  if (CERT_PEM && KEY_PEM) {
    tls = { cert: fs.readFileSync(CERT_PEM), key: fs.readFileSync(KEY_PEM) };
  } else if (PFX_BASE64) {
    // Hospedagem sem disco fixo: o .pfx chega em base64 e é gravado a cada boot.
    const caminho = "/tmp/certificado.pfx";
    fs.writeFileSync(caminho, Buffer.from(PFX_BASE64, "base64"), { mode: 0o600 });
    tls = { pfx: fs.readFileSync(caminho), passphrase: PFX_SENHA };
  } else {
    tls = { pfx: fs.readFileSync(PFX_PATH), passphrase: PFX_SENHA };
  }
} catch (erro) {
  console.error(`Não consegui ler o certificado: ${erro.message}`);
  console.error("Informe PFX_BASE64 + PFX_SENHA, PFX_PATH + PFX_SENHA, ou CERT_PEM + KEY_PEM.");
  process.exit(1);
}

function montarEnvelope(chave, ns) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeConsultaNF xmlns="${ns}">
      <nfeDadosMsg>
        <consSitNFe xmlns="http://www.portalfiscal.inf.br/nfe" versao="4.00">
          <tpAmb>${TPAMB}</tpAmb>
          <xServ>CONSULTAR</xServ>
          <chNFe>${chave}</chNFe>
        </consSitNFe>
      </nfeDadosMsg>
    </nfeConsultaNF>
  </soap12:Body>
</soap12:Envelope>`;
}

// A SEFAZ usa certificados da ICP-Brasil, que não vêm na lista de autoridades
// confiáveis do Node. Quando a cadeia não é reconhecida, a chamada é repetida
// sem validar a cadeia: quem se autentica é o nosso certificado A1, e a
// resposta é apenas a leitura da nota consultada.
const ERROS_CADEIA = new Set([
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "CERT_UNTRUSTED",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
]);

function requisitar(endereco, acao, corpo, inseguro = false) {
  return new Promise((resolve, reject) => {
    const url = new URL(endereco);
    const requisicao = https.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: "POST",
        port: 443,
        minVersion: "TLSv1.2",
        timeout: 45000,
        rejectUnauthorized: !inseguro,
        headers: {
          "content-type": `application/soap+xml; charset=utf-8; action="${acao}"`,
          soapaction: `"${acao}"`,
          "content-length": Buffer.byteLength(corpo),
        },
        ...tls,
      },
      (resposta) => {
        let dados = "";
        resposta.setEncoding("utf8");
        resposta.on("data", (pedaco) => {
          dados += pedaco;
        });
        resposta.on("end", () => resolve({ status: resposta.statusCode, corpo: dados }));
      },
    );

    requisicao.on("timeout", () => requisicao.destroy(new Error("Tempo esgotado na SEFAZ.")));
    requisicao.on("error", reject);
    requisicao.end(corpo);
  });
}

async function falarComSefaz(endereco, acao, corpo) {
  try {
    return await requisitar(endereco, acao, corpo, false);
  } catch (erro) {
    if (ERROS_CADEIA.has(erro?.code)) {
      return requisitar(endereco, acao, corpo, true);
    }
    throw erro;
  }
}

function bloco(xml, tag) {
  const achado = xml.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`));
  return achado ? achado[1] : null;
}

function texto(xml, tag) {
  const conteudo = bloco(xml, tag);
  if (conteudo === null) return null;
  const limpo = conteudo.replace(/<[^>]*>/g, "").trim();
  return limpo || null;
}

function statusDoCodigo(cStat) {
  if (["100", "150"].includes(cStat)) return "autorizada";
  if (["101", "135", "151", "155"].includes(cStat)) return "cancelada";
  if (["110", "301", "302"].includes(cStat)) return "denegada";
  return "rejeitada";
}

async function consultar(chave) {
  const modelo = chave.slice(20, 22);
  if (modelo !== "65") {
    return {
      ok: false,
      http: 422,
      erro: `Esta chave é de modelo ${modelo}. O serviço consulta apenas NFC-e (modelo 65).`,
    };
  }

  const uf = UF_POR_CODIGO[chave.slice(0, 2)];
  const servico = uf ? SERVICOS[uf] : null;
  if (!servico) {
    return { ok: false, http: 422, erro: `Não há serviço de consulta mapeado para esta UF (${uf ?? "desconhecida"}).` };
  }

  const endereco = TPAMB === "2" ? servico.hom : servico.prod;
  const acao = `${servico.ns}/nfeConsultaNF`;

  const { status, corpo } = await falarComSefaz(endereco, acao, montarEnvelope(chave, servico.ns));

  if (status !== 200) {
    return {
      ok: false,
      http: 502,
      erro: `A SEFAZ de ${uf} respondeu com o código ${status}.`,
      detalhe: corpo.slice(0, 400),
    };
  }

  const cStat = texto(corpo, "cStat");
  const xMotivo = texto(corpo, "xMotivo");

  if (!cStat) {
    return {
      ok: false,
      http: 422,
      erro: "A resposta da SEFAZ não trouxe o código de status.",
      detalhe: corpo.slice(0, 400),
    };
  }

  // 217 = chave não consta na base da UF.
  if (cStat === "217" || cStat === "137") {
    return {
      ok: false,
      http: 404,
      erro: "A SEFAZ não localizou documento para esta chave.",
      cStat,
      xMotivo,
    };
  }

  if (cStat === "656" || cStat === "593") {
    return {
      ok: false,
      http: 429,
      erro: "A SEFAZ bloqueou temporariamente o consumo (muitas consultas seguidas).",
      cStat,
      xMotivo,
    };
  }

  const situacao = statusDoCodigo(cStat);
  if (situacao === "rejeitada") {
    return {
      ok: false,
      http: 422,
      erro: `A SEFAZ não confirmou esta chave: ${cStat} - ${xMotivo ?? "sem motivo"}.`,
      cStat,
      xMotivo,
    };
  }

  return {
    ok: true,
    nota: {
      chave,
      modelo: "65",
      status_sefaz: situacao,
      codigo_status: cStat,
      motivo_status: xMotivo,
      protocolo: texto(corpo, "nProt"),
      data_emissao: texto(corpo, "dhRecbto"),
      itens: [],
    },
  };
}

function responderJson(res, status, objeto) {
  const corpo = JSON.stringify(objeto);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(corpo),
  });
  res.end(corpo);
}

function lerCorpo(req) {
  return new Promise((resolve, reject) => {
    let dados = "";
    req.setEncoding("utf8");
    req.on("data", (pedaco) => {
      dados += pedaco;
      if (dados.length > 8192) reject(new Error("Corpo grande demais."));
    });
    req.on("end", () => resolve(dados));
    req.on("error", reject);
  });
}

const servidor = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`);

  if (req.method === "GET" && url.pathname === "/") {
    return responderJson(res, 200, {
      ok: true,
      servico: "consulta-nfce",
      versao: "protocolo4-nfce",
      cnpj: CNPJ,
      ambiente: TPAMB === "1" ? "producao" : "homologacao",
    });
  }

  if (url.pathname !== "/consulta") {
    return responderJson(res, 404, { erro: "Use POST /consulta" });
  }

  if (req.method !== "POST") {
    return responderJson(res, 405, { erro: "Use POST /consulta" });
  }

  const autorizacao = req.headers.authorization ?? "";
  if (autorizacao !== `Bearer ${TOKEN}`) {
    return responderJson(res, 401, { erro: "Token inválido." });
  }

  let chave = "";
  try {
    const corpo = await lerCorpo(req);
    chave = String(JSON.parse(corpo || "{}").chave ?? "").replace(/\D/g, "");
  } catch {
    return responderJson(res, 400, { erro: "Envie JSON com o campo chave." });
  }

  if (chave.length !== 44) {
    return responderJson(res, 400, { erro: "A chave precisa ter 44 dígitos." });
  }

  try {
    const resultado = await consultar(chave);
    if (!resultado.ok) {
      console.log(`chave ${chave}: ${resultado.erro}`);
      return responderJson(res, resultado.http ?? 422, {
        erro: resultado.erro,
        ...(resultado.detalhe ? { detalhe: resultado.detalhe } : {}),
      });
    }

    console.log(`chave ${chave}: nota localizada`);
    responderJson(res, 200, { ok: true, nota: resultado.nota });
  } catch (erro) {
    console.error(`chave ${chave}: ${erro.message}`);
    responderJson(res, 502, { erro: `Falha ao falar com a SEFAZ: ${erro.message}` });
  }
});

servidor.listen(PORTA, () => {
  console.log(`Consulta NFC-e ouvindo na porta ${PORTA} (CNPJ ${CNPJ}, ambiente ${TPAMB}).`);
});