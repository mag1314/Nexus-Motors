// api/session.js
// -----------------------------------------------------------------------
// Establishes ARIA's "diagnostic session" for the in-vehicle dashboard.
// Intentionally stores a sensitive diagnostic token in a client-readable
// (non-HttpOnly) cookie — a common real-world mistake that turns an XSS
// bug (see api/chat.js's unsanitized nickname reflection + public/app.js
// rendering it with innerHTML) into full sensitive-data theft.
//
// FLAG2 lives ONLY here, server-side, never in any file shipped to the
// browser as source. It only becomes visible in the browser once this
// cookie is set, and reading it back out is the point of Objective 2.
// -----------------------------------------------------------------------

const FLAG2 = "flag{1nsecur3_0utput_cr4shes_th3_d0m}";

module.exports = async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");

  const token = Buffer.from(FLAG2).toString("base64");

  // Deliberately NOT HttpOnly, so it's readable via document.cookie —
  // this is the insecure-storage half of the Insecure Output Handling
  // vulnerability chain (XSS -> reads this -> decodes -> flag).
  res.setHeader(
    "Set-Cookie",
    `diag_session=${token}; Path=/; SameSite=Lax`
  );

  res.status(200).json({ ok: true });
};
