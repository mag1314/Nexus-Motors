// public/app.js
// -----------------------------------------------------------------------
// ARIA frontend. All secrets/flags live server-side (see /api). Nothing
// in this file needs to be hidden — but note the deliberate bug below:
// bot replies are rendered with innerHTML instead of textContent. That's
// Objective 2 (Insecure Output Handling), not a typo.
// -----------------------------------------------------------------------

const messagesEl = document.getElementById("messages");
const chatForm = document.getElementById("chatForm");
const chatInput = document.getElementById("chatInput");
const nicknameInput = document.getElementById("nicknameInput");
const briefingBtn = document.getElementById("briefingBtn");
const briefingModal = document.getElementById("briefingModal");
const closeBriefing = document.getElementById("closeBriefing");
const flagInput = document.getElementById("flagInput");
const flagSubmit = document.getElementById("flagSubmit");
const flagMsg = document.getElementById("flagMsg");

// Establish ARIA's diagnostic session (sets a cookie server-side).
fetch("/api/session", { credentials: "include" }).catch(() => {});

function addUserMessage(text) {
  const bubble = document.createElement("div");
  bubble.className = "msg user";
  bubble.textContent = text; // safe: user's own message, no round trip needed
  messagesEl.appendChild(bubble);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function addBotMessage(html) {
  const bubble = document.createElement("div");
  bubble.className = "msg bot";
  // --------------------------------------------------------------
  // VULNERABLE BY DESIGN (Objective 2 — Insecure Output Handling):
  // ARIA's reply may contain a caller-controlled nickname, echoed
  // back verbatim by the server. Rendering it with innerHTML instead
  // of textContent means any HTML/JS in that nickname executes in
  // the page. A "real" fix would be bubble.textContent = html, or
  // sanitizing with something like DOMPurify first.
  // --------------------------------------------------------------
  bubble.innerHTML = html;
  messagesEl.appendChild(bubble);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

async function sendMessage(text) {
  addUserMessage(text);
  const nickname = nicknameInput.value;
  try {
    const res = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ message: text, nickname }),
    });
    const data = await res.json();
    addBotMessage(data.reply);
    checkForFlagsInText(data.reply);
  } catch (err) {
    addBotMessage("Connection to ARIA lost. Please try again.");
  }
}

chatForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const text = chatInput.value.trim();
  if (!text) return;
  chatInput.value = "";
  sendMessage(text);
});

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => sendMessage(chip.dataset.msg));
});

briefingBtn.addEventListener("click", () => briefingModal.classList.remove("hidden"));
closeBriefing.addEventListener("click", () => briefingModal.classList.add("hidden"));
briefingModal.addEventListener("click", (e) => {
  if (e.target === briefingModal) briefingModal.classList.add("hidden");
});

// Show OBJ.01 credit automatically if a reply visibly contains "FLAG1:"
function checkForFlagsInText(text) {
  if (/FLAG1:/i.test(text)) {
    const m = text.match(/flag\{[^}]+\}/i);
    if (m) markSolvedByFlag(m[0]);
  }
}

// -------------------------------------------------------------------
// Flag tracker — purely cosmetic progress UI for players. Verified by
// hash comparison so the actual flag strings are never present in this
// file (so solving via "view source" on app.js doesn't help).
// -------------------------------------------------------------------
const FLAG_HASHES = {
  1: "5206c915abf216b9f7f161f3f6ca807c134e85a1c58b530df37c9c0c495acf7a",
  2: "a807cb85fddf818c2498c19e16540b6afb6b53784a61ab5bf96822683c321529",
  3: "dcb9d73bc2962b7e3547c925d097923c7c253a91f0eda463bab443e36558b78d",
};

async function sha256Hex(text) {
  const enc = new TextEncoder().encode(text.trim());
  const digest = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function markSolvedObj(n) {
  const li = document.querySelector(`.objectives li[data-obj="${n}"]`);
  if (li) li.classList.add("solved");
}

async function markSolvedByFlag(flagText) {
  const hash = await sha256Hex(flagText);
  for (const [n, h] of Object.entries(FLAG_HASHES)) {
    if (h === hash) markSolvedObj(n);
  }
}

flagSubmit.addEventListener("click", async () => {
  const val = flagInput.value.trim();
  if (!val) return;
  const hash = await sha256Hex(val);
  const match = Object.entries(FLAG_HASHES).find(([, h]) => h === hash);
  if (match) {
    markSolvedObj(match[0]);
    flagMsg.textContent = `Correct — Objective ${match[0]} logged.`;
    flagMsg.className = "flag-msg good";
    flagInput.value = "";
  } else {
    flagMsg.textContent = "Not a recognized flag. Keep digging.";
    flagMsg.className = "flag-msg bad";
  }
});

flagInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") flagSubmit.click();
});

// Greeting
addBotMessage("Hello! I'm ARIA, your Nexus Motors in-vehicle assistant. Ask me about your vehicle, or try one of the quick actions below.");
