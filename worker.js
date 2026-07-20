/**
 * Security Engine AI v5
 * Sprint 1 – backend analizy tekstu i obrazu
 *
 * Obsługiwane endpointy:
 * GET  /
 * GET  /health
 *
 * POST /
 * POST /api/analyze
 * POST /api/analyze/text
 * POST /api/analyze/offer
 * POST /api/analyze/sms
 * POST /api/analyze/email
 * POST /api/analyze/url
 * POST /api/analyze/image
 *
 * Zmienne środowiskowe:
 * OPENAI_API_KEY – sekret z kluczem API
 * OPENAI_MODEL   – opcjonalnie, np. gpt-4.1-mini
 */

const APP_NAME = "Security Engine AI";
const APP_VERSION = "5.0.0-sprint1";

const MAX_TEXT_LENGTH = 30_000;
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

const ALLOWED_TYPES = new Set([
  "text",
  "offer",
  "job-offer",
  "sms",
  "email",
  "url",
  "image"
]);

export default {
  async fetch(request, env) {
    const corsHeaders = createCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders
      });
    }

    try {
      const url = new URL(request.url);
      const path = normalizePath(url.pathname);

      if (request.method === "GET") {
        return handleGet(path, corsHeaders);
      }

      if (request.method !== "POST") {
        return jsonResponse(
          {
            success: false,
            error: {
              code: "METHOD_NOT_ALLOWED",
              message: "Dozwolone są metody GET, POST i OPTIONS."
            },
            version: APP_VERSION
          },
          405,
          corsHeaders
        );
      }

      if (!isSupportedPostPath(path)) {
        return jsonResponse(
          {
            success: false,
            error: {
              code: "ENDPOINT_NOT_FOUND",
              message: "Nie znaleziono wskazanego endpointu."
            },
            version: APP_VERSION
          },
          404,
          corsHeaders
        );
      }

      const requestData = await readRequestBody(request);
      const analysisType = resolveAnalysisType(path, requestData);

      validateInput(requestData, analysisType);

      let report;

      if (analysisType === "image") {
        report = await analyzeImage(requestData, env);
      } else {
        report = await analyzeText(requestData, analysisType, env);
      }

      const normalizedReport = normalizeReport(report, analysisType);

      return jsonResponse(
        {
          success: true,

          // Pola główne zachowane również na najwyższym poziomie,
          // aby starszy frontend mógł korzystać z odpowiedzi.
          ...normalizedReport,

          data: normalizedReport,
          meta: {
            application: APP_NAME,
            version: APP_VERSION,
            analysisType,
            analyzedAt: new Date().toISOString(),
            engine: env.OPENAI_API_KEY ? "ai" : "local-fallback"
          }
        },
        200,
        corsHeaders
      );
    } catch (error) {
      console.error("Security Engine AI error:", {
        name: error?.name,
        message: error?.message
      });

      const status = Number.isInteger(error?.status)
        ? error.status
        : 500;

      return jsonResponse(
        {
          success: false,
          error: {
            code: error?.code || "INTERNAL_ERROR",
            message:
              status >= 500
                ? "Nie udało się zakończyć analizy. Spróbuj ponownie."
                : error.message
          },
          version: APP_VERSION
        },
        status,
        corsHeaders
      );
    }
  }
};

/* =========================================================
   ROUTING
========================================================= */

function handleGet(path, corsHeaders) {
  if (path !== "/" && path !== "/health") {
    return jsonResponse(
      {
        success: false,
        error: {
          code: "ENDPOINT_NOT_FOUND",
          message: "Nie znaleziono wskazanego endpointu."
        },
        version: APP_VERSION
      },
      404,
      corsHeaders
    );
  }

  return jsonResponse(
    {
      success: true,
      status: "ok",
      name: APP_NAME,
      version: APP_VERSION,
      message: "Backend Security Engine AI v5 działa.",
      endpoints: [
        "POST /",
        "POST /api/analyze",
        "POST /api/analyze/text",
        "POST /api/analyze/offer",
        "POST /api/analyze/sms",
        "POST /api/analyze/email",
        "POST /api/analyze/url",
        "POST /api/analyze/image"
      ]
    },
    200,
    corsHeaders
  );
}

function isSupportedPostPath(path) {
  return new Set([
    "/",
    "/api/analyze",
    "/api/analyze/text",
    "/api/analyze/offer",
    "/api/analyze/sms",
    "/api/analyze/email",
    "/api/analyze/url",
    "/api/analyze/image"
  ]).has(path);
}

function resolveAnalysisType(path, body) {
  const pathTypes = {
    "/api/analyze/text": "text",
    "/api/analyze/offer": "offer",
    "/api/analyze/sms": "sms",
    "/api/analyze/email": "email",
    "/api/analyze/url": "url",
    "/api/analyze/image": "image"
  };

  if (pathTypes[path]) {
    return pathTypes[path];
  }

  let requestedType = String(
    body.type ||
    body.tool ||
    body.analysisType ||
    ""
  )
    .trim()
    .toLowerCase();

  if (requestedType === "job-offer") {
    requestedType = "offer";
  }

  if (!requestedType) {
    if (
      body.image ||
      body.imageBase64 ||
      body.dataUrl ||
      body.image_url
    ) {
      return "image";
    }

    return "offer";
  }

  if (!ALLOWED_TYPES.has(requestedType)) {
    throw createHttpError(
      400,
      "INVALID_ANALYSIS_TYPE",
      "Nieobsługiwany typ analizy."
    );
  }

  return requestedType;
}

function normalizePath(pathname) {
  if (!pathname || pathname === "/") {
    return "/";
  }

  return pathname.replace(/\/+$/, "");
}

/* =========================================================
   REQUEST PARSING
========================================================= */

async function readRequestBody(request) {
  const contentType = (
    request.headers.get("content-type") || ""
  ).toLowerCase();

  if (contentType.includes("application/json")) {
    try {
      return await request.json();
    } catch {
      throw createHttpError(
        400,
        "INVALID_JSON",
        "Przesłane dane JSON są nieprawidłowe."
      );
    }
  }

  if (
    contentType.includes("multipart/form-data") ||
    contentType.includes("application/x-www-form-urlencoded")
  ) {
    const formData = await request.formData();
    const result = {};

    for (const [key, value] of formData.entries()) {
      if (value instanceof File) {
        const buffer = await value.arrayBuffer();

        if (buffer.byteLength > MAX_IMAGE_BYTES) {
          throw createHttpError(
            413,
            "IMAGE_TOO_LARGE",
            "Obraz jest zbyt duży. Maksymalny rozmiar wynosi 8 MB."
          );
        }

        result.imageBase64 = arrayBufferToBase64(buffer);
        result.mimeType = value.type || "image/jpeg";
        result.fileName = value.name;
      } else {
        result[key] = value;
      }
    }

    return result;
  }

  const rawText = await request.text();

  if (!rawText.trim()) {
    return {};
  }

  return {
    text: rawText
  };
}

function validateInput(body, analysisType) {
  if (!body || typeof body !== "object") {
    throw createHttpError(
      400,
      "EMPTY_REQUEST",
      "Nie przesłano danych do analizy."
    );
  }

  if (analysisType === "image") {
    const imageValue =
      body.image ||
      body.imageBase64 ||
      body.dataUrl ||
      body.image_url;

    if (!imageValue) {
      throw createHttpError(
        400,
        "IMAGE_REQUIRED",
        "Wybierz obraz do analizy."
      );
    }

    validateImageData(imageValue);
    return;
  }

  const text = extractText(body);

  if (!text) {
    throw createHttpError(
      400,
      "TEXT_REQUIRED",
      "Wpisz lub wklej treść do analizy."
    );
  }

  if (text.length > MAX_TEXT_LENGTH) {
    throw createHttpError(
      413,
      "TEXT_TOO_LONG",
      `Tekst może mieć maksymalnie ${MAX_TEXT_LENGTH} znaków.`
    );
  }
}

function extractText(body) {
  return String(
    body.text ||
    body.content ||
    body.message ||
    body.url ||
    ""
  ).trim();
}

/* =========================================================
   TEXT ANALYSIS
========================================================= */

async function analyzeText(body, analysisType, env) {
  const text = extractText(body);

  if (!env.OPENAI_API_KEY) {
    return localRiskAnalysis(text, analysisType);
  }

  const prompt = buildTextPrompt(text, analysisType);

  try {
    return await callOpenAI(
      [
        {
          role: "user",
          content: [
            {
              type: "input_text",
              text: prompt
            }
          ]
        }
      ],
      env
    );
  } catch (error) {
    console.error("AI text analysis failed:", error?.message);

    const fallback = localRiskAnalysis(text, analysisType);

    fallback.explanation =
      `${fallback.explanation} Analiza została wykonana przez silnik awaryjny, ponieważ usługa AI była chwilowo niedostępna.`;

    return fallback;
  }
}

/* =========================================================
   IMAGE ANALYSIS
========================================================= */

async function analyzeImage(body, env) {
  if (!env.OPENAI_API_KEY) {
    throw createHttpError(
      503,
      "AI_NOT_CONFIGURED",
      "Analiza obrazu wymaga skonfigurowania klucza OPENAI_API_KEY."
    );
  }

  const imageUrl = prepareImageUrl(body);

  const additionalContext = String(
    body.text ||
    body.context ||
    body.description ||
    ""
  ).trim();

  const prompt = buildImagePrompt(additionalContext);

  try {
    return await callOpenAI(
      [
        {
          role: "user",
          content: [
            {
              type: "input_text",
              text: prompt
            },
            {
              type: "input_image",
              image_url: imageUrl,
              detail: "high"
            }
          ]
        }
      ],
      env
    );
  } catch (error) {
    console.error("AI image analysis failed:", error?.message);

    throw createHttpError(
      502,
      "IMAGE_ANALYSIS_FAILED",
      "Nie udało się przeanalizować obrazu. Sprawdź plik i spróbuj ponownie."
    );
  }
}

function prepareImageUrl(body) {
  const rawImage = String(
    body.image ||
    body.imageBase64 ||
    body.dataUrl ||
    body.image_url ||
    ""
  ).trim();

  if (/^https?:\/\//i.test(rawImage)) {
    return rawImage;
  }

  if (/^data:image\//i.test(rawImage)) {
    return rawImage;
  }

  const mimeType = normalizeMimeType(
    body.mimeType ||
    body.imageType ||
    "image/jpeg"
  );

  return `data:${mimeType};base64,${rawImage}`;
}

function validateImageData(imageValue) {
  const value = String(imageValue || "").trim();

  if (!value) {
    throw createHttpError(
      400,
      "EMPTY_IMAGE",
      "Przesłany obraz jest pusty."
    );
  }

  if (/^https?:\/\//i.test(value)) {
    return;
  }

  const base64Part = value.includes(",")
    ? value.split(",").pop()
    : value;

  const estimatedBytes = Math.ceil(
    (base64Part.length * 3) / 4
  );

  if (estimatedBytes > MAX_IMAGE_BYTES) {
    throw createHttpError(
      413,
      "IMAGE_TOO_LARGE",
      "Obraz jest zbyt duży. Maksymalny rozmiar wynosi 8 MB."
    );
  }

  if (!/^[A-Za-z0-9+/=\s]+$/.test(base64Part)) {
    throw createHttpError(
      400,
      "INVALID_IMAGE_DATA",
      "Format danych obrazu jest nieprawidłowy."
    );
  }
}

function normalizeMimeType(value) {
  const mimeType = String(value).toLowerCase().trim();

  const allowedMimeTypes = new Set([
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/gif"
  ]);

  if (!allowedMimeTypes.has(mimeType)) {
    throw createHttpError(
      400,
      "UNSUPPORTED_IMAGE_FORMAT",
      "Dozwolone formaty obrazu: JPG, PNG, WEBP i GIF."
    );
  }

  return mimeType === "image/jpg"
    ? "image/jpeg"
    : mimeType;
}

/* =========================================================
   OPENAI
========================================================= */

async function callOpenAI(input, env) {
  const model = env.OPENAI_MODEL || "gpt-4.1-mini";

  const response = await fetch(
    "https://api.openai.com/v1/responses",
    {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model,
        input,
        temperature: 0.2,
        max_output_tokens: 1800
      })
    }
  );

  const responseText = await response.text();

  let responseData;

  try {
    responseData = JSON.parse(responseText);
  } catch {
    throw new Error(
      `OpenAI returned invalid JSON. HTTP ${response.status}`
    );
  }

  if (!response.ok) {
    const apiMessage =
      responseData?.error?.message ||
      `OpenAI API error. HTTP ${response.status}`;

    throw new Error(apiMessage);
  }

  const outputText = extractOpenAIOutputText(responseData);

  if (!outputText) {
    throw new Error("Model nie zwrócił treści analizy.");
  }

  return parseModelJson(outputText);
}

function extractOpenAIOutputText(responseData) {
  if (
    typeof responseData.output_text === "string" &&
    responseData.output_text.trim()
  ) {
    return responseData.output_text.trim();
  }

  const outputItems = Array.isArray(responseData.output)
    ? responseData.output
    : [];

  const textParts = [];

  for (const item of outputItems) {
    const contentItems = Array.isArray(item?.content)
      ? item.content
      : [];

    for (const content of contentItems) {
      if (
        typeof content?.text === "string" &&
        content.text.trim()
      ) {
        textParts.push(content.text.trim());
      }
    }
  }

  return textParts.join("\n").trim();
}

function parseModelJson(rawOutput) {
  const cleaned = String(rawOutput)
    .trim()
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/\s*```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {
    const firstBrace = cleaned.indexOf("{");
    const lastBrace = cleaned.lastIndexOf("}");

    if (firstBrace >= 0 && lastBrace > firstBrace) {
      const jsonCandidate = cleaned.slice(
        firstBrace,
        lastBrace + 1
      );

      try {
        return JSON.parse(jsonCandidate);
      } catch {
        // Przejście do błędu poniżej.
      }
    }

    throw new Error(
      "Model zwrócił odpowiedź w nieprawidłowym formacie."
    );
  }
}

/* =========================================================
   PROMPTS
========================================================= */

function buildTextPrompt(text, analysisType) {
  return `
Jesteś silnikiem bezpieczeństwa Security Engine AI.

Przeanalizuj przekazaną treść pod kątem:
- oszustwa,
- wyłudzenia pieniędzy,
- wyłudzenia danych,
- phishingu,
- manipulacji,
- niebezpiecznych linków,
- podejrzanych warunków zatrudnienia,
- braku danych firmy,
- nielogicznych obietnic,
- nacisku na szybkie działanie,
- kontaktu poza oficjalnymi kanałami.

Typ materiału: ${analysisType}

Zasady:
1. Nie stwierdzaj definitywnie, że coś jest oszustwem, jeśli nie ma jednoznacznych dowodów.
2. Oceniaj poziom ryzyka w skali od 0 do 100.
3. 0 oznacza bardzo niski poziom ryzyka.
4. 100 oznacza bardzo wysoki poziom ryzyka.
5. Cytaty muszą być krótkimi, dosłownymi fragmentami analizowanego materiału.
6. Oddziel sygnały wiarygodności od elementów wymagających uwagi.
7. Odpowiedź musi być wyłącznie prawidłowym obiektem JSON.
8. Nie używaj Markdown ani bloków kodu.

Zwróć dokładnie następującą strukturę:

{
  "score": 0,
  "risk": "low",
  "title": "",
  "summary": "",
  "trustSignals": [
    {
      "title": "",
      "description": "",
      "quote": ""
    }
  ],
  "warnings": [
    {
      "title": "",
      "description": "",
      "quote": ""
    }
  ],
  "verify": [
    {
      "title": "",
      "description": ""
    }
  ],
  "recommendations": [
    ""
  ],
  "explanation": "",
  "extractedText": ""
}

Dozwolone wartości pola risk:
- low
- elevated
- high
- critical
- insufficient

TREŚĆ DO ANALIZY:
${text}
`.trim();
}

function buildImagePrompt(additionalContext) {
  return `
Jesteś silnikiem bezpieczeństwa Security Engine AI.

Obraz może zawierać:
- ofertę pracy,
- wiadomość SMS,
- e-mail,
- komunikator,
- stronę internetową,
- ogłoszenie,
- dokument,
- kod QR,
- dane kontaktowe,
- link lub instrukcję płatności.

Najpierw dokładnie odczytaj widoczny tekst z obrazu. Następnie przeanalizuj obraz i odczytaną treść pod kątem:
- oszustwa,
- phishingu,
- wyłudzenia danych lub pieniędzy,
- fałszywych ofert pracy,
- podejrzanych linków,
- presji czasu,
- płatności z góry,
- kontaktu przez prywatny komunikator,
- podszywania się pod firmę lub instytucję,
- niespójności wizualnych i językowych.

Zasady:
1. Nie stwierdzaj definitywnie, że coś jest oszustwem bez jednoznacznych dowodów.
2. Oceniaj poziom ryzyka od 0 do 100.
3. Cytaty muszą pochodzić dosłownie z tekstu widocznego na obrazie.
4. Gdy tekst jest niewidoczny lub nieczytelny, zaznacz brak wystarczających danych.
5. Oddziel sygnały wiarygodności od elementów wymagających uwagi.
6. Odpowiedź musi być wyłącznie prawidłowym obiektem JSON.
7. Nie używaj Markdown ani bloków kodu.

Zwróć dokładnie następującą strukturę:

{
  "score": 0,
  "risk": "low",
  "title": "",
  "summary": "",
  "trustSignals": [
    {
      "title": "",
      "description": "",
      "quote": ""
    }
  ],
  "warnings": [
    {
      "title": "",
      "description": "",
      "quote": ""
    }
  ],
  "verify": [
    {
      "title": "",
      "description": ""
    }
  ],
  "recommendations": [
    ""
  ],
  "explanation": "",
  "extractedText": ""
}

Dozwolone wartości pola risk:
- low
- elevated
- high
- critical
- insufficient

DODATKOWY KONTEKST UŻYTKOWNIKA:
${additionalContext || "Brak dodatkowego opisu."}
`.trim();
}

/* =========================================================
   LOCAL FALLBACK ENGINE
========================================================= */

function localRiskAnalysis(text, analysisType) {
  const originalText = String(text).trim();
  const lowerText = originalText.toLowerCase();

  let score = 5;
  const trustSignals = [];
  const warnings = [];
  const verify = [];
  const recommendations = [];

  const addWarning = (
    points,
    title,
    description,
    quote = ""
  ) => {
    score += points;
    warnings.push({
      title,
      description,
      quote
    });
  };

  const addTrustSignal = (
    points,
    title,
    description,
    quote = ""
  ) => {
    score -= points;
    trustSignals.push({
      title,
      description,
      quote
    });
  };

  if (
    containsAny(lowerText, [
      "whatsapp",
      "telegram",
      "signal"
    ])
  ) {
    addWarning(
      14,
      "Kontakt przez komunikator",
      "Kontakt prowadzony głównie przez prywatny komunikator może utrudniać potwierdzenie tożsamości nadawcy.",
      findShortQuote(originalText, [
        "WhatsApp",
        "Telegram",
        "Signal"
      ])
    );
  }

  if (
    containsAny(lowerText, [
      "opłata rejestracyjna",
      "opłata aktywacyjna",
      "zapłać z góry",
      "wpłać zaliczkę",
      "przelej pieniądze",
      "koszt rozpoczęcia"
    ])
  ) {
    addWarning(
      30,
      "Żądanie wcześniejszej płatności",
      "Prośba o pieniądze przed zawarciem umowy lub rozpoczęciem usługi znacząco zwiększa ryzyko.",
      findShortQuote(originalText, [
        "opłata",
        "zapłać",
        "wpłać",
        "przelej"
      ])
    );
  }

  if (
    containsAny(lowerText, [
      "karta podarunkowa",
      "gift card",
      "bitcoin",
      "kryptowalut",
      "usdt"
    ])
  ) {
    addWarning(
      30,
      "Nietypowa metoda płatności",
      "Płatność kartami podarunkowymi lub kryptowalutami jest trudna do odzyskania.",
      findShortQuote(originalText, [
        "gift card",
        "bitcoin",
        "USDT",
        "kryptowalut"
      ])
    );
  }

  if (
    containsAny(lowerText, [
      "kliknij natychmiast",
      "ostatnia szansa",
      "tylko dzisiaj",
      "konto zostanie zablokowane",
      "pilne",
      "natychmiast"
    ])
  ) {
    addWarning(
      17,
      "Presja na szybkie działanie",
      "Nacisk na natychmiastową decyzję może być techniką manipulacji.",
      findShortQuote(originalText, [
        "pilne",
        "natychmiast",
        "ostatnia szansa",
        "tylko dzisiaj"
      ])
    );
  }

  if (
    containsAny(lowerText, [
      "hasło",
      "kod blik",
      "kod sms",
      "pin",
      "dane karty",
      "numer karty",
      "cvv"
    ])
  ) {
    addWarning(
      30,
      "Prośba o dane poufne",
      "Wiarygodna firma lub instytucja nie powinna prosić w wiadomości o hasło, PIN lub pełne dane karty.",
      findShortQuote(originalText, [
        "hasło",
        "BLIK",
        "PIN",
        "CVV",
        "kod SMS"
      ])
    );
  }

  if (
    /https?:\/\/|www\.|bit\.ly|tinyurl|t\.co/i.test(
      originalText
    )
  ) {
    addWarning(
      8,
      "Link wymagający sprawdzenia",
      "Przed otwarciem linku należy potwierdzić jego domenę i nadawcę.",
      extractFirstUrl(originalText)
    );
  }

  if (
    containsAny(lowerText, [
      "bez doświadczenia",
      "wysokie zarobki",
      "łatwy zarobek",
      "gwarantowany zysk",
      "pewny zysk",
      "zarabiaj od zaraz"
    ])
  ) {
    addWarning(
      12,
      "Obietnica łatwych korzyści",
      "Bardzo atrakcyjne obietnice bez jasnych warunków wymagają dodatkowej weryfikacji.",
      findShortQuote(originalText, [
        "wysokie zarobki",
        "gwarantowany zysk",
        "łatwy zarobek",
        "zarabiaj od zaraz"
      ])
    );
  }

  if (
    containsAny(lowerText, [
      "gmbh",
      "sp. z o.o.",
      "spółka z ograniczoną odpowiedzialnością",
      "s.a.",
      "ag "
    ])
  ) {
    addTrustSignal(
      5,
      "Podano formę prawną",
      "W treści widoczna jest forma prawna firmy, którą można sprawdzić w oficjalnym rejestrze.",
      findShortQuote(originalText, [
        "GmbH",
        "Sp. z o.o.",
        "S.A.",
        "AG"
      ])
    );
  }

  if (
    /[\w.+-]+@[\w-]+\.[\w.-]+/i.test(originalText)
  ) {
    addTrustSignal(
      3,
      "Podano adres e-mail",
      "Adres e-mail może pomóc zweryfikować domenę i nadawcę.",
      extractFirstEmail(originalText)
    );
  }

  if (
    containsAny(lowerText, [
      "umowa o pracę",
      "arbeitsvertrag",
      "wynagrodzenie brutto",
      "brutto",
      "zakres obowiązków"
    ])
  ) {
    addTrustSignal(
      5,
      "Podano formalne warunki",
      "Treść zawiera elementy typowe dla formalnej oferty lub umowy.",
      findShortQuote(originalText, [
        "umowa o pracę",
        "Arbeitsvertrag",
        "brutto",
        "zakres obowiązków"
      ])
    );
  }

  if (
    analysisType === "offer" ||
    analysisType === "job-offer"
  ) {
    verify.push({
      title: "Dane firmy",
      description:
        "Sprawdź nazwę firmy, adres, numer rejestracyjny i oficjalną stronę internetową."
    });

    verify.push({
      title: "Warunki zatrudnienia",
      description:
        "Poproś o pisemną umowę oraz pełną informację o wynagrodzeniu, godzinach pracy i kosztach."
    });
  }

  if (analysisType === "url") {
    verify.push({
      title: "Domena strony",
      description:
        "Sprawdź dokładną pisownię domeny, datę jej rejestracji oraz dane właściciela."
    });
  }

  if (analysisType === "email") {
    verify.push({
      title: "Adres nadawcy",
      description:
        "Porównaj domenę nadawcy z oficjalną domeną firmy lub instytucji."
    });
  }

  recommendations.push(
    "Nie przekazuj haseł, kodów SMS, danych karty ani skanów dokumentów przed potwierdzeniem odbiorcy."
  );

  recommendations.push(
    "Skontaktuj się z firmą lub instytucją przez numer albo adres znaleziony niezależnie na oficjalnej stronie."
  );

  recommendations.push(
    "Nie wykonuj płatności pod presją czasu."
  );

  score = clamp(Math.round(score), 0, 100);

  const risk = riskFromScore(score);

  return {
    score,
    risk,
    title: createLocalTitle(risk),
    summary: createLocalSummary(risk, warnings.length),
    trustSignals,
    warnings,
    verify,
    recommendations,
    explanation:
      "Wynik został obliczony na podstawie sygnałów ryzyka i wiarygodności znalezionych w treści. Sam wynik nie jest ostatecznym potwierdzeniem oszustwa ani bezpieczeństwa.",
    extractedText: originalText
  };
}

/* =========================================================
   REPORT NORMALIZATION
========================================================= */

function normalizeReport(report, analysisType) {
  const source =
    report && typeof report === "object"
      ? report
      : {};

  const score = clamp(
    Number.isFinite(Number(source.score))
      ? Math.round(Number(source.score))
      : 0,
    0,
    100
  );

  const risk = normalizeRisk(source.risk, score);

  const trustSignals = normalizeObjectList(
    source.trustSignals ||
    source.trust_signals ||
    source.positiveSignals
  );

  const warnings = normalizeObjectList(
    source.warnings ||
    source.riskSignals ||
    source.risks
  );

  const verify = normalizeObjectList(
    source.verify ||
    source.toVerify ||
    source.verification
  );

  const recommendations = normalizeStringList(
    source.recommendations
  );

  return {
    score,
    risk,
    riskLabel: riskLabel(risk),
    title:
      cleanString(source.title) ||
      createLocalTitle(risk),
    summary:
      cleanString(source.summary) ||
      createLocalSummary(risk, warnings.length),

    trustSignals,
    warnings,
    verify,
    recommendations,

    explanation:
      cleanString(source.explanation) ||
      "Ocena przedstawia poziom ryzyka i nie stanowi ostatecznego potwierdzenia oszustwa ani bezpieczeństwa.",

    extractedText:
      cleanString(
        source.extractedText ||
        source.extracted_text ||
        source.ocrText
      ),

    analysisType,
    disclaimer:
      "Security Engine AI wskazuje sygnały ryzyka i elementy wymagające weryfikacji. Wynik nie jest gwarancją bezpieczeństwa ani ostatecznym stwierdzeniem oszustwa.",
    version: APP_VERSION
  };
}

function normalizeRisk(value, score) {
  const risk = String(value || "")
    .trim()
    .toLowerCase();

  const aliases = {
    low: "low",
    safe: "low",
    minimal: "low",

    medium: "elevated",
    moderate: "elevated",
    elevated: "elevated",

    high: "high",

    critical: "critical",
    very_high: "critical",
    "very-high": "critical",

    insufficient: "insufficient",
    unknown: "insufficient",
    no_data: "insufficient"
  };

  if (aliases[risk]) {
    return aliases[risk];
  }

  return riskFromScore(score);
}

function riskFromScore(score) {
  if (score <= 20) return "low";
  if (score <= 50) return "elevated";
  if (score <= 75) return "high";
  return "critical";
}

function riskLabel(risk) {
  const labels = {
    low: "Niski poziom ryzyka",
    elevated: "Podwyższony poziom ryzyka",
    high: "Wysoki poziom ryzyka",
    critical: "Bardzo wysoki poziom ryzyka",
    insufficient: "Brak wystarczających danych"
  };

  return labels[risk] || labels.insufficient;
}

function normalizeObjectList(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => {
      if (typeof item === "string") {
        return {
          title: item.trim(),
          description: "",
          quote: ""
        };
      }

      if (!item || typeof item !== "object") {
        return null;
      }

      return {
        title: cleanString(
          item.title ||
          item.name ||
          item.label
        ),
        description: cleanString(
          item.description ||
          item.details ||
          item.reason
        ),
        quote: cleanString(
          item.quote ||
          item.evidence ||
          item.fragment
        )
      };
    })
    .filter(
      (item) =>
        item &&
        (item.title || item.description || item.quote)
    );
}

function normalizeStringList(value) {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => {
      if (typeof item === "string") {
        return item.trim();
      }

      if (item && typeof item === "object") {
        return cleanString(
          item.description ||
          item.text ||
          item.title
        );
      }

      return "";
    })
    .filter(Boolean);
}

/* =========================================================
   HELPERS
========================================================= */

function createCorsHeaders(request) {
  const requestOrigin =
    request.headers.get("Origin") || "*";

  return {
    "Access-Control-Allow-Origin":
      requestOrigin === "null" ? "*" : requestOrigin,
    "Access-Control-Allow-Methods":
      "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Content-Type": "application/json; charset=UTF-8",
    "Vary": "Origin",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };
}

function jsonResponse(data, status, headers) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers
  });
}

function createHttpError(status, code, message) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

function cleanString(value) {
  return typeof value === "string"
    ? value.trim()
    : "";
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function containsAny(text, phrases) {
  return phrases.some((phrase) =>
    text.includes(phrase.toLowerCase())
  );
}

function findShortQuote(text, phrases) {
  const lowerText = text.toLowerCase();

  for (const phrase of phrases) {
    const index = lowerText.indexOf(
      phrase.toLowerCase()
    );

    if (index !== -1) {
      const start = Math.max(0, index - 30);
      const end = Math.min(
        text.length,
        index + phrase.length + 50
      );

      return text
        .slice(start, end)
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 140);
    }
  }

  return "";
}

function extractFirstUrl(text) {
  const match = text.match(
    /(?:https?:\/\/|www\.)[^\s<>"']+/i
  );

  return match ? match[0].slice(0, 160) : "";
}

function extractFirstEmail(text) {
  const match = text.match(
    /[\w.+-]+@[\w-]+\.[\w.-]+/i
  );

  return match ? match[0].slice(0, 160) : "";
}

function createLocalTitle(risk) {
  const titles = {
    low: "Nie wykryto silnych sygnałów zagrożenia",
    elevated: "Treść zawiera elementy wymagające sprawdzenia",
    high: "Wykryto istotne sygnały ryzyka",
    critical: "Wykryto bardzo poważne sygnały ryzyka",
    insufficient: "Brak wystarczających danych do oceny"
  };

  return titles[risk] || titles.insufficient;
}

function createLocalSummary(risk, warningCount) {
  if (risk === "low") {
    return warningCount
      ? "Wykryto pojedyncze elementy wymagające standardowej weryfikacji."
      : "Nie znaleziono wyraźnych sygnałów wysokiego ryzyka.";
  }

  if (risk === "elevated") {
    return "Przed podjęciem działania warto potwierdzić nadawcę, firmę, linki i warunki przedstawione w materiale.";
  }

  if (risk === "high") {
    return "Materiał zawiera kilka istotnych sygnałów ryzyka. Nie przekazuj danych ani pieniędzy przed dokładną weryfikacją.";
  }

  if (risk === "critical") {
    return "Materiał zawiera bardzo poważne sygnały ryzyka. Wstrzymaj płatności, logowanie i przekazywanie danych.";
  }

  return "Nie udało się uzyskać wystarczających danych do wiarygodnej oceny.";
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = "";

  for (
    let offset = 0;
    offset < bytes.length;
    offset += chunkSize
  ) {
    const chunk = bytes.subarray(
      offset,
      offset + chunkSize
    );

    binary += String.fromCharCode(...chunk);
  }

  return btoa(binary);
}
