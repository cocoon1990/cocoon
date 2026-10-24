/**
 * popup.js — UI حداقلی: اتصال / قطع / وضعیت
 *
 * هیچ منطق رمزنگاری اینجا نیست: همه‌چیز در background.js و Wasm است.
 * (popup هر بار باز/بسته می‌شود، پس نگه‌داشتن کلید در آن اشتباه است.)
 */

const $ = (id) => document.getElementById(id);

const dot = $("dot");
const statusText = $("status-text");
const meta = $("meta");
const btnConnect = $("btn-connect");
const btnDisconnect = $("btn-disconnect");

function setUI({ dotClass, text, metaText = "", connected, busy = false }) {
  dot.className = `dot ${dotClass || ""}`.trim();
  statusText.textContent = text;
  meta.textContent = metaText;
  btnConnect.disabled = busy || connected;
  btnDisconnect.disabled = busy || !connected;
}

function send(type, extra = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...extra }, (response) => {
      if (chrome.runtime.lastError) {
        resolve({ ok: false, error: chrome.runtime.lastError.message });
        return;
      }
      resolve(response || { ok: false, error: "no response" });
    });
  });
}

async function refresh() {
  const res = await send("STATUS");

  if (!res.ok) {
    setUI({ dotClass: "dot--err", text: "خطا در ارتباط با background", metaText: res.error, connected: false });
    return;
  }

  const s = res.data;

  if (!s.connected) {
    setUI({ dotClass: "", text: "قطع", connected: false });
    return;
  }

  setUI({
    dotClass: "dot--ok",
    text: `متصل${s.configVersion ? ` · config ${s.configVersion}` : ""}`,
    metaText: `${s.version} · keys در storage.session${s.hydrated ? " · بازسازی شد" : ""}`,
    connected: true,
  });
}

btnConnect.addEventListener("click", async () => {
  setUI({ dotClass: "dot--busy", text: "در حال handshake...", connected: false, busy: true });

  const res = await send("CONNECT");
  if (!res.ok) {
    setUI({ dotClass: "dot--err", text: "اتصال ناموفق", metaText: res.error, connected: false });
    return;
  }

  // اثبات عملی: یک درخواست امضاشده به مقصد مجاز
  setUI({ dotClass: "dot--busy", text: "بررسی تونل...", connected: true, busy: true });

  const probe = await send("SIGNED_FETCH", { target: "https://www.youtube.com/robots.txt" });

  if (probe.ok && probe.data.ok) {
    setUI({
      dotClass: "dot--ok",
      text: `متصل · تونل تأیید شد (HTTP ${probe.data.status})`,
      metaText: `path=${probe.data.path || "?"} · ${res.data.configVersion || ""}`,
      connected: true,
    });
  } else {
    const detail = probe.ok ? `HTTP ${probe.data.status}` : probe.error;
    setUI({
      dotClass: "dot--err",
      text: "متصل، اما تونل تأیید نشد",
      metaText: detail,
      connected: true,
    });
  }
});

btnDisconnect.addEventListener("click", async () => {
  setUI({ dotClass: "dot--busy", text: "در حال قطع...", connected: true, busy: true });

  const res = await send("DISCONNECT");
  if (!res.ok) {
    setUI({ dotClass: "dot--err", text: "خطا در قطع", metaText: res.error, connected: true });
    return;
  }

  setUI({ dotClass: "", text: "قطع شد · کلیدها پاک شدند", connected: false });
});

refresh();
