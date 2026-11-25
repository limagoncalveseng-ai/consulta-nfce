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
 * Usa o serviço oficial de distribuição de documentos fiscais (Ambiente
 * Nacional), que é o caminho correto para um ERP: nada de captcha.
 *
 * Sem dependências. Rode com Node 18 ou superior:  node server.js
 */

const http = require("node:http");
const https = require("node:https");
const fs = require("node:fs");
const zlib = require("node:zlib");

const PORTA = Number(process.env.PORT || 8787);
const TOKEN = process.env.TOKEN || "";
const PFX_PATH = process.env.PFX_PATH || "./certificado.pfx";
const PFX_SENHA = process.env.PFX_SENHA || "";
const CERT_PEM = process.env.CERT_PEM || "";
const KEY_PEM = process.env.KEY_PEM || "";
const PFX_BASE64 = process.env.PFX_BASE64 || "";
const CNPJ = (process.env.CNPJ || "").replace(/\D/g, "");
const CUFAUTOR = (process.env.CUFAUTOR || "31").padStart(2, "0"); // 31 = MG
const TPAMB = process.env.TPAMB || "1"; // 1 = produção, 2 = homologação

const URL_DISTRIBUICAO =
  "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx";
const ACAO =
  "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe/nfeDistDFeInteresse";

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

function montarEnvelope(chave) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDistDFeInteresse xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
      <nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>${TPAMB}</tpAmb>
          <cUFAutor>${CUFAUTOR}</cUFAutor>
          <CNPJ>${CNPJ}</CNPJ>
          <consChNFe><chNFe>${chave}</chNFe></consChNFe>
        </distDFeInt>
      </nfeDadosMsg>
    </nfeDistDFeInteresse>
  </soap12:Body>
</soap12:Envelope>`;
}

function requisitar(corpo) {
  return new Promise((resolve, reject) => {
    const url = new URL(URL_DISTRIBUICAO);
    const requisicao = https.request(
      {
        hostname: url.hostname,
        path: url.pathname,
        method: "POST",
        port: 443,
        minVersion: "TLSv1.2",
        timeout: 45000,
        headers: {
          "content-type": `application/soap+xml; charset=utf-8; action="${ACAO}"`,
          soapaction: `"${ACAO}"`,
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

async function consultar(chave) {
  const { status, corpo } = await requisitar(montarEnvelope(chave));

  if (status !== 200) {
    return {
      ok: false,
      http: 502,
      erro: `A SEFAZ respondeu com o código ${status}.`,
      detalhe: corpo.slice(0, 400),
    };
  }

  const cStat = texto(corpo, "cStat");
  const xMotivo = texto(corpo, "xMotivo");

  if (cStat !== "138") {
    const mensagem =
      cStat === "137"
        ? "A SEFAZ não localizou documento para esta chave."
        : cStat === "656"
          ? "A SEFAZ bloqueou temporariamente o consumo (muitas consultas seguidas)."
          : `A SEFAZ não devolveu a nota: ${cStat ?? "sem código"} - ${xMotivo ?? "sem motivo"}.`;
    return { ok: false, http: cStat === "137" ? 404 : 422, erro: mensagem, cStat, xMotivo };
  }

  const doc = corpo.match(/<docZip([^>]*)>([\s\S]*?)<\/docZip>/);
  if (!doc) {
    return { ok: false, http: 422, erro: "A SEFAZ não devolveu o documento da nota." };
  }

  const schema = (doc[1].match(/schema="([^"]+)"/) || [])[1] || null;

  let xml;
  try {
    xml = zlib.gunzipSync(Buffer.from(doc[2].replace(/\s+/g, ""), "base64")).toString("utf8");
  } catch {
    return { ok: false, http: 422, erro: "Não consegui descompactar o documento devolvido." };
  }

  if (!xml.includes("<nfeProc")) {
    return {
      ok: false,
      http: 422,
      erro: `A SEFAZ devolveu um documento sem a nota completa (${schema ?? "schema desconhecido"}).`,
    };
  }

  return { ok: true, xml };
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
    res.writeHead(200, {
      "content-type": "application/xml; charset=utf-8",
      "content-length": Buffer.byteLength(resultado.xml),
    });
    res.end(resultado.xml);
  } catch (erro) {
    console.error(`chave ${chave}: ${erro.message}`);
    responderJson(res, 502, { erro: `Falha ao falar com a SEFAZ: ${erro.message}` });
  }
});

servidor.listen(PORTA, () => {
  console.log(`Consulta NFC-e ouvindo na porta ${PORTA} (CNPJ ${CNPJ}, UF autor ${CUFAUTOR}).`);
});