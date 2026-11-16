/**
 * SSB LINE OA Tenant Gateway — core logic (pure; no Google services used directly).
 * All side effects go through the 'deps' object so the same code runs in Apps Script
 * (see Main.gs) and in the offline test harness (tests/run_tests.js).
 *
 * Security model
 *  - The LINE user ID is NEVER taken from the browser. The LIFF page sends a LINE ID token;
 *    the server verifies it with LINE (deps.verifyIdToken) and uses the 'sub' it returns.
 *  - OTPs are 6 digits, stored only as SHA-256(pepper|userId|room|otp), expire after
 *    OTP_TTL_MIN, max OTP_MAX_ATTEMPTS wrong tries, one active OTP per user.
 *  - requestOtp answers the same generic message whether or not the room/email matched
 *    (no tenant enumeration). Emails are never returned to the browser.
 *  - One ACTIVE primary LINE account per room, one room per LINE account.
 *  - Revocation: any ACTIVE binding whose room is no longer ACTIVE in the registry
 *    (or whose check-out date has passed) is revoked and its tenant rich menu unlinked.
 */

var GW = (function () {
  var OTP_TTL_MIN = 10;
  var OTP_MAX_ATTEMPTS = 5;
  var OTP_MAX_REQUESTS_PER_HOUR = 3;   // per LINE user
  var ROOM_RE = /^(A1(0[1-9]|1[0-9]|2[0-3])|F2(0[1-9]|1[0-2]))$/;

  var MSG = {
    otpSent: 'หากเลขห้องและอีเมลตรงกับทะเบียนผู้เช่า ระบบได้ส่งรหัส 6 หลักไปที่อีเมลที่ลงทะเบียนไว้แล้ว (หมดอายุใน ' + OTP_TTL_MIN + ' นาที)',
    badInput: 'กรุณากรอกเลขห้อง (เช่น A101) และอีเมลให้ถูกต้อง',
    tooMany: 'ขอรหัสบ่อยเกินไป กรุณารอ 1 ชั่วโมง หรือติดต่อฝ่ายบริหาร',
    noOtp: 'ไม่พบรหัสที่ใช้งานได้ กรุณาขอรหัสใหม่',
    expired: 'รหัสหมดอายุแล้ว กรุณาขอรหัสใหม่',
    wrongOtp: 'รหัสไม่ถูกต้อง',
    locked: 'กรอกรหัสผิดเกินกำหนด กรุณาขอรหัสใหม่',
    roomTaken: 'ห้องนี้มีบัญชี LINE หลักลงทะเบียนแล้ว กรุณาติดต่อฝ่ายบริหาร',
    userTaken: 'บัญชี LINE นี้ยืนยันกับห้องอื่นอยู่แล้ว กรุณาติดต่อฝ่ายบริหาร',
    notActive: 'ห้องนี้ไม่มีสถานะผู้เช่าปัจจุบัน กรุณาติดต่อฝ่ายบริหาร',
    verified: 'ยืนยันตัวตนสำเร็จ เมนูผู้เช่าจะแสดงในแชท',
    badToken: 'ไม่สามารถยืนยันบัญชี LINE ได้ กรุณาเปิดหน้านี้จากเมนูใน LINE @276orarq'
  };

  function normRoom(r) { return String(r || '').toUpperCase().replace(/[\s\-_/]/g, ''); }
  function normEmail(e) { return String(e || '').trim().toLowerCase(); }
  function validEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e); }
  function shortId(u) { return u ? String(u).slice(0, 6) + '…' : ''; }

  function isRoomActive(reg, now) {
    if (!reg) return false;
    if (String(reg.status || '').toUpperCase() !== 'ACTIVE') return false;
    if (reg.checkout) {
      var co = new Date(reg.checkout);
      if (!isNaN(co) && co.getTime() < now.getTime()) return false;
    }
    return true;
  }

  function hashOtp(deps, userId, room, otp) {
    return deps.sha256(deps.pepper + '|' + userId + '|' + room + '|' + otp);
  }

  function resolveUser(deps, idToken) {
    if (!idToken) return null;
    var r = deps.verifyIdToken(idToken);       // returns {sub} or null
    return r && r.sub ? r.sub : null;
  }

  /** Step 1: tenant asks for an OTP. */
  function requestOtp(deps, p) {
    var now = deps.now();
    var userId = resolveUser(deps, p.idToken);
    if (!userId) return { ok: false, code: 'BAD_TOKEN', message: MSG.badToken };
    var room = normRoom(p.room), email = normEmail(p.email);
    if (!ROOM_RE.test(room) || !validEmail(email)) return { ok: false, code: 'BAD_INPUT', message: MSG.badInput };

    var recent = deps.store.countOtpRequests(userId, new Date(now.getTime() - 3600e3));
    if (recent >= OTP_MAX_REQUESTS_PER_HOUR) {
      deps.store.audit('OTP_RATE_LIMIT', room, shortId(userId), '');
      return { ok: false, code: 'RATE_LIMIT', message: MSG.tooMany };
    }
    deps.store.logOtpRequest(userId, now);

    var reg = deps.registry.get(room);
    var match = reg && isRoomActive(reg, now) && normEmail(reg.email) === email && email !== '';
    if (match) {
      var otp = deps.randomOtp();
      deps.store.putOtp({
        userId: userId, room: room, hash: hashOtp(deps, userId, room, otp),
        expiresAt: new Date(now.getTime() + OTP_TTL_MIN * 60e3), attempts: 0, createdAt: now
      });
      deps.sendMail(reg.email, room, otp, OTP_TTL_MIN);
      deps.store.audit('OTP_SENT', room, shortId(userId), '');
    } else {
      deps.store.audit('OTP_NO_MATCH', room, shortId(userId), reg ? (isRoomActive(reg, now) ? 'email_mismatch' : 'room_not_active') : 'room_not_in_registry');
    }
    // Same answer either way: no enumeration of rooms/emails.
    return { ok: true, code: 'OTP_REQUESTED', message: MSG.otpSent };
  }

  /** Step 2: tenant submits the OTP. */
  function verifyOtp(deps, p) {
    var now = deps.now();
    var userId = resolveUser(deps, p.idToken);
    if (!userId) return { ok: false, code: 'BAD_TOKEN', message: MSG.badToken };
    var room = normRoom(p.room), otp = String(p.otp || '').replace(/\D/g, '');

    var rec = deps.store.getOtp(userId);
    if (!rec || rec.room !== room || rec.used) return { ok: false, code: 'NO_OTP', message: MSG.noOtp };
    if (rec.expiresAt.getTime() < now.getTime()) {
      deps.store.deleteOtp(userId);
      deps.store.audit('OTP_EXPIRED', room, shortId(userId), '');
      return { ok: false, code: 'EXPIRED', message: MSG.expired };
    }
    if (rec.attempts >= OTP_MAX_ATTEMPTS) {
      deps.store.deleteOtp(userId);
      return { ok: false, code: 'LOCKED', message: MSG.locked };
    }
    if (otp.length !== 6 || hashOtp(deps, userId, room, otp) !== rec.hash) {
      var attempts = rec.attempts + 1;
      deps.store.updateOtpAttempts(userId, attempts);
      deps.store.audit('OTP_WRONG', room, shortId(userId), 'attempt ' + attempts);
      if (attempts >= OTP_MAX_ATTEMPTS) { deps.store.deleteOtp(userId); return { ok: false, code: 'LOCKED', message: MSG.locked }; }
      return { ok: false, code: 'WRONG_OTP', message: MSG.wrongOtp, attemptsLeft: OTP_MAX_ATTEMPTS - attempts };
    }

    // OTP correct — re-check the registry at the moment of binding.
    var reg = deps.registry.get(room);
    if (!isRoomActive(reg, now)) { deps.store.deleteOtp(userId); return { ok: false, code: 'NOT_ACTIVE', message: MSG.notActive }; }

    var byRoom = deps.store.activeBindingForRoom(room);
    if (byRoom && byRoom.userId !== userId) {
      deps.store.deleteOtp(userId);
      deps.store.audit('DUPLICATE_ROOM', room, shortId(userId), 'held by ' + shortId(byRoom.userId));
      return { ok: false, code: 'ROOM_TAKEN', message: MSG.roomTaken };
    }
    var byUser = deps.store.activeBindingForUser(userId);
    if (byUser && byUser.room !== room) {
      deps.store.deleteOtp(userId);
      deps.store.audit('DUPLICATE_USER', room, shortId(userId), 'already ' + byUser.room);
      return { ok: false, code: 'USER_TAKEN', message: MSG.userTaken };
    }

    deps.store.deleteOtp(userId);
    if (!byRoom) deps.store.addBinding({ room: room, userId: userId, status: 'ACTIVE', verifiedAt: now });
    deps.linkTenantMenu(userId);
    deps.store.audit('VERIFIED', room, shortId(userId), byRoom ? 're-verify' : 'new');
    return { ok: true, code: 'VERIFIED', message: MSG.verified, room: room };
  }

  /** Tenant page: who am I? Server-side authorization for any tenant-only content. */
  function status(deps, p) {
    var userId = resolveUser(deps, p.idToken);
    if (!userId) return { ok: false, code: 'BAD_TOKEN', message: MSG.badToken };
    var b = deps.store.activeBindingForUser(userId);
    if (!b) return { ok: true, code: 'NOT_VERIFIED', verified: false };
    var reg = deps.registry.get(b.room);
    if (!isRoomActive(reg, deps.now())) {        // registry changed since last revocation sweep
      revokeBinding(deps, b, 'registry_not_active');
      return { ok: true, code: 'REVOKED', verified: false };
    }
    return { ok: true, code: 'VERIFIED', verified: true, room: b.room };
  }

  function revokeBinding(deps, b, reason) {
    deps.store.revokeBinding(b.room, b.userId, deps.now(), reason);
    deps.unlinkTenantMenu(b.userId);
    deps.store.audit('REVOKED', b.room, shortId(b.userId), reason);
  }

  /** Daily trigger + manual: revoke bindings for rooms that are no longer ACTIVE. */
  function revokeCheckedOut(deps) {
    var now = deps.now(), n = 0;
    deps.store.activeBindings().forEach(function (b) {
      if (!isRoomActive(deps.registry.get(b.room), now)) { revokeBinding(deps, b, 'checked_out_or_vacant'); n++; }
    });
    return n;
  }

  /** Owner-only manual revoke (e.g. lost phone, wrong person). */
  function revokeRoom(deps, room, reason) {
    var b = deps.store.activeBindingForRoom(normRoom(room));
    if (!b) return false;
    revokeBinding(deps, b, reason || 'owner_manual');
    return true;
  }

  return {
    requestOtp: requestOtp, verifyOtp: verifyOtp, status: status,
    revokeCheckedOut: revokeCheckedOut, revokeRoom: revokeRoom,
    _isRoomActive: isRoomActive, _normRoom: normRoom, MSG: MSG,
    OTP_TTL_MIN: OTP_TTL_MIN, OTP_MAX_ATTEMPTS: OTP_MAX_ATTEMPTS
  };
})();

/**
 * SSB LINE OA Tenant Gateway — Apps Script wiring (web app + Sheets + Mail + LINE API).
 *
 * Script Properties (Project Settings → Script properties) — set by the OWNER, never in code:
 *   LOGIN_CHANNEL_ID     LINE Login channel ID that hosts the LIFF app (same provider as the OA)
 *   MSG_CHANNEL_TOKEN    Messaging API long-lived channel access token (for rich-menu link/unlink)
 *   TENANT_RICHMENU_ID   richmenu-… ID returned by setupTenantRichMenu()
 *   GATEWAY_SHEET_ID     Spreadsheet holding BINDINGS / OTP / OTP_REQ / AUDIT tabs (created by setupGatewaySheet())
 *   REGISTRY_SHEET_ID    Existing tenant registry spreadsheet (BSS MASTER)
 *   REGISTRY_TAB         Tab name with columns ROOM | EMAIL | STATUS | CHECKOUT_DATE  (default LINE_ACCESS)
 *   OTP_PEPPER           Long random secret (generated by setupGatewaySheet())
 *
 * Deploy: Deploy → New deployment → Web app → Execute as: Me · Who has access: Anyone.
 * The web app only accepts JSON actions; every tenant action is authorised by a LINE ID token
 * verified with LINE's server, so "Anyone" access does not expose tenant data.
 */

function P_(k, d) { var v = PropertiesService.getScriptProperties().getProperty(k); return v == null ? d : v; }

function doGet(e) {
  var out = { ok: true, service: 'SSB LINE gateway', version: '1.1' };
  if (e && e.parameter && e.parameter.action === 'availability') {
    try { out = availability_(); } catch (err) { console.error(err); out = { ok: false, code: 'SERVER_ERROR' }; }
  }
  return ContentService.createTextOutput(JSON.stringify(out)).setMimeType(ContentService.MimeType.JSON);
}

/** LIFF page posts text/plain JSON (avoids CORS preflight): {action, idToken, room, email, otp} */
function doPost(e) {
  var out;
  var lock = LockService.getScriptLock();
  try {
    lock.waitLock(20000);
    var p = JSON.parse((e && e.postData && e.postData.contents) || '{}');
    var deps = buildDeps_();
    if (p.action === 'requestOtp') out = GW.requestOtp(deps, p);
    else if (p.action === 'verifyOtp') out = GW.verifyOtp(deps, p);
    else if (p.action === 'status') out = GW.status(deps, p);
    else out = { ok: false, code: 'UNKNOWN_ACTION' };
  } catch (err) {
    console.error(err);
    out = { ok: false, code: 'SERVER_ERROR', message: 'ระบบขัดข้อง กรุณาลองใหม่ หรือติดต่อฝ่ายบริหาร' };
  } finally {
    try { lock.releaseLock(); } catch (x) {}
  }
  return ContentService.createTextOutput(JSON.stringify(out)).setMimeType(ContentService.MimeType.JSON);
}

// ---------------------------------------------------------------- deps

function buildDeps_() {
  return {
    now: function () { return new Date(); },
    pepper: P_('OTP_PEPPER', ''),
    sha256: function (s) {
      return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, s, Utilities.Charset.UTF_8)
        .map(function (b) { return ('0' + (b & 255).toString(16)).slice(-2); }).join('');
    },
    randomOtp: function () {
      // Utilities.getUuid() is backed by a CSPRNG; take 6 decimal digits from it.
      var hex = Utilities.getUuid().replace(/-/g, '').slice(0, 12);
      return ('000000' + (parseInt(hex, 16) % 1000000)).slice(-6);
    },
    verifyIdToken: verifyIdToken_,
    sendMail: sendOtpMail_,
    linkTenantMenu: function (userId) { lineApi_('post', '/v2/bot/user/' + userId + '/richmenu/' + P_('TENANT_RICHMENU_ID')); },
    unlinkTenantMenu: function (userId) { lineApi_('delete', '/v2/bot/user/' + userId + '/richmenu'); },
    registry: registry_(),
    store: store_()
  };
}

function verifyIdToken_(idToken) {
  var res = UrlFetchApp.fetch('https://api.line.me/oauth2/v2.1/verify', {
    method: 'post', muteHttpExceptions: true,
    payload: { id_token: idToken, client_id: P_('LOGIN_CHANNEL_ID') }
  });
  if (res.getResponseCode() !== 200) return null;
  var j = JSON.parse(res.getContentText());
  return j && j.sub ? { sub: j.sub } : null;
}

function sendOtpMail_(to, room, otp, ttl) {
  MailApp.sendEmail({
    to: to,
    subject: 'รหัสยืนยันผู้เช่า บ้านสุขสมบูรณ์ (SSB) ห้อง ' + room,
    name: 'บ้านสุขสมบูรณ์ SSB',
    body: 'รหัสยืนยันของท่านคือ ' + otp + '\n\nใช้ได้ภายใน ' + ttl + ' นาที สำหรับยืนยันบัญชี LINE @276orarq กับห้อง ' + room +
      '\nห้ามแจ้งรหัสนี้กับผู้อื่น เจ้าหน้าที่จะไม่ขอรหัสนี้จากท่าน\nหากท่านไม่ได้ขอรหัส ไม่ต้องดำเนินการใด ๆ\n\nบ้านสุขสมบูรณ์ (SSB) · LINE @276orarq · โทร 081-733-7699'
  });
}

function lineApi_(method, path, payload) {
  var opt = { method: method, muteHttpExceptions: true, headers: { Authorization: 'Bearer ' + P_('MSG_CHANNEL_TOKEN') } };
  if (payload !== undefined) { opt.contentType = 'application/json'; opt.payload = JSON.stringify(payload); }
  var res = UrlFetchApp.fetch('https://api.line.me' + path, opt);
  if (res.getResponseCode() >= 300) console.warn('LINE API ' + method + ' ' + path + ' → ' + res.getResponseCode() + ' ' + res.getContentText());
  return res;
}

// ---------------------------------------------------------------- registry (read-only)

function registry_() {
  var rows = null;
  function load() {
    if (rows) return rows;
    rows = {};
    var sh = SpreadsheetApp.openById(P_('REGISTRY_SHEET_ID')).getSheetByName(P_('REGISTRY_TAB', 'LINE_ACCESS'));
    var v = sh.getDataRange().getValues();
    var h = v[0].map(function (x) { return String(x).trim().toUpperCase(); });
    var iR = h.indexOf('ROOM'), iE = h.indexOf('EMAIL'), iS = h.indexOf('STATUS'), iC = h.indexOf('CHECKOUT_DATE');
    for (var i = 1; i < v.length; i++) {
      var room = GW._normRoom(v[i][iR]);
      if (!room) continue;
      rows[room] = { room: room, email: String(v[i][iE] || ''), status: String(v[i][iS] || ''), checkout: iC >= 0 && v[i][iC] ? v[i][iC] : '' };
    }
    return rows;
  }
  return { get: function (room) { return load()[room] || null; } };
}

// ---------------------------------------------------------------- gateway store (BINDINGS / OTP / OTP_REQ / AUDIT)

function store_() {
  var ss = SpreadsheetApp.openById(P_('GATEWAY_SHEET_ID'));
  function sh(n) { return ss.getSheetByName(n); }
  function rows(n) { var v = sh(n).getDataRange().getValues(); return v.slice(1); }
  function findRow(n, pred) { var v = sh(n).getDataRange().getValues(); for (var i = 1; i < v.length; i++) if (pred(v[i])) return i + 1; return 0; }
  // BINDINGS: room | lineUserId | status | verifiedAt | revokedAt | reason
  function toB(r) { return { room: r[0], userId: r[1], status: r[2] }; }
  return {
    countOtpRequests: function (userId, since) { return rows('OTP_REQ').filter(function (r) { return r[0] === userId && new Date(r[1]) >= since; }).length; },
    logOtpRequest: function (userId, at) { sh('OTP_REQ').appendRow([userId, at]); },
    // OTP: lineUserId | room | hash | expiresAt | attempts | createdAt
    putOtp: function (o) { var r = findRow('OTP', function (x) { return x[0] === o.userId; }); if (r) sh('OTP').deleteRow(r); sh('OTP').appendRow([o.userId, o.room, o.hash, o.expiresAt, o.attempts, o.createdAt]); },
    getOtp: function (userId) { var x = rows('OTP').filter(function (r) { return r[0] === userId; })[0]; return x ? { userId: x[0], room: x[1], hash: x[2], expiresAt: new Date(x[3]), attempts: Number(x[4]) } : null; },
    updateOtpAttempts: function (userId, n) { var r = findRow('OTP', function (x) { return x[0] === userId; }); if (r) sh('OTP').getRange(r, 5).setValue(n); },
    deleteOtp: function (userId) { var r = findRow('OTP', function (x) { return x[0] === userId; }); if (r) sh('OTP').deleteRow(r); },
    activeBindings: function () { return rows('BINDINGS').filter(function (r) { return r[2] === 'ACTIVE'; }).map(toB); },
    activeBindingForRoom: function (room) { return this.activeBindings().filter(function (b) { return b.room === room; })[0] || null; },
    activeBindingForUser: function (userId) { return this.activeBindings().filter(function (b) { return b.userId === userId; })[0] || null; },
    addBinding: function (b) { sh('BINDINGS').appendRow([b.room, b.userId, 'ACTIVE', b.verifiedAt, '', '']); },
    revokeBinding: function (room, userId, at, reason) {
      var r = findRow('BINDINGS', function (x) { return x[0] === room && x[1] === userId && x[2] === 'ACTIVE'; });
      if (r) sh('BINDINGS').getRange(r, 3, 1, 4).setValues([['REVOKED', sh('BINDINGS').getRange(r, 4).getValue(), at, reason]]);
    },
    audit: function (ev, room, uid, detail) { sh('AUDIT').appendRow([new Date(), ev, room, uid, detail]); }
  };
}

// ---------------------------------------------------------------- owner-run setup & admin (run from the editor)

/** 1) Creates the gateway spreadsheet + tabs and a random OTP pepper. Safe to run once. */
function setupGatewaySheet() {
  var props = PropertiesService.getScriptProperties();
  if (!props.getProperty('GATEWAY_SHEET_ID')) {
    var ss = SpreadsheetApp.create('SSB_LINE_GATEWAY_DATA (ห้ามแชร์)');
    var tabs = { BINDINGS: ['room', 'lineUserId', 'status', 'verifiedAt', 'revokedAt', 'reason'],
                 OTP: ['lineUserId', 'room', 'hash', 'expiresAt', 'attempts', 'createdAt'],
                 OTP_REQ: ['lineUserId', 'requestedAt'],
                 AUDIT: ['at', 'event', 'room', 'lineUser(short)', 'detail'] };
    var first = true;
    Object.keys(tabs).forEach(function (n) {
      var s = first ? ss.getSheets()[0].setName(n) : ss.insertSheet(n); first = false;
      s.getRange(1, 1, 1, tabs[n].length).setValues([tabs[n]]).setFontWeight('bold'); s.setFrozenRows(1);
    });
    props.setProperty('GATEWAY_SHEET_ID', ss.getId());
  }
  if (!props.getProperty('OTP_PEPPER')) props.setProperty('OTP_PEPPER', Utilities.getUuid() + Utilities.getUuid());
  Logger.log('Gateway sheet: https://docs.google.com/spreadsheets/d/' + props.getProperty('GATEWAY_SHEET_ID'));
}

/** 2) Creates the TENANT rich menu via the Messaging API and uploads its image from Drive. */
function setupTenantRichMenu(imageFileId, liffUrl) {
  var w = 2500, h = 1686, cw = Math.round(w / 3), ch = h / 2;
  function area(col, row, action) { return { bounds: { x: col * cw, y: row * ch, width: col === 2 ? w - 2 * cw : cw, height: ch }, action: action }; }
  var body = {
    size: { width: w, height: h }, selected: true, name: 'SSB Tenant Menu v1', chatBarText: 'เมนูผู้เช่า',
    areas: [
      area(0, 0, { type: 'message', label: 'แจ้งซ่อม', text: 'แจ้งซ่อม' }),
      area(1, 0, { type: 'message', label: 'ประกาศอาคาร', text: 'ประกาศอาคาร' }),
      area(2, 0, { type: 'message', label: 'ค่าเช่า/บิล', text: 'ชำระเงิน' }),
      area(0, 1, { type: 'uri', label: 'ห้องของฉัน', uri: liffUrl }),
      area(1, 1, { type: 'message', label: 'ติดต่อฝ่ายบริหาร', text: 'ติดต่อ' }),
      area(2, 1, { type: 'message', label: 'ข้อมูลทั่วไป', text: 'ถามตอบ' })
    ]
  };
  var res = lineApi_('post', '/v2/bot/richmenu', body);
  var id = JSON.parse(res.getContentText()).richMenuId;
  var blob = DriveApp.getFileById(imageFileId).getBlob();
  UrlFetchApp.fetch('https://api-data.line.me/v2/bot/richmenu/' + id + '/content', {
    method: 'post', contentType: blob.getContentType(), payload: blob.getBytes(),
    headers: { Authorization: 'Bearer ' + P_('MSG_CHANNEL_TOKEN') }
  });
  PropertiesService.getScriptProperties().setProperty('TENANT_RICHMENU_ID', id);
  Logger.log('TENANT_RICHMENU_ID = ' + id);
}

/** 3) Daily revocation sweep — install once with installDailyRevocation(). */
function revokeCheckedOut() { var n = GW.revokeCheckedOut(buildDeps_()); Logger.log('revoked ' + n); }
function installDailyRevocation() {
  ScriptApp.getProjectTriggers().forEach(function (t) { if (t.getHandlerFunction() === 'revokeCheckedOut') ScriptApp.deleteTrigger(t); });
  ScriptApp.newTrigger('revokeCheckedOut').timeBased().everyDays(1).atHour(6).create();
}

/** Owner manual revoke, e.g. revokeRoomManual('A101'). */
function revokeRoomManual(room) { Logger.log(GW.revokeRoom(buildDeps_(), room, 'owner_manual') ? 'revoked ' + room : 'no active binding for ' + room); }

// ---------------------------------------------------------------- SSB one-click setup (run in this order from the Run menu)
/** Step 1: run setupGatewaySheet (creates the private data sheet). */
/** Step 2: create the tenant rich menu with the SSB image + LIFF link. */
function step2_setupTenantRichMenuSSB() { setupTenantRichMenu('1WuXbvqjXb6I9bFO9lugz7i9WtGkCFcDp', 'https://liff.line.me/2012636052-SHKZSKR5'); }
/** Step 3: run installDailyRevocation. */


// ---------------------------------------------------------------- public room availability (no personal data)
/**
 * GET <web app>?action=availability → { ok, asOf, rooms:[{room, type, from, until, state}] }
 * Reads ROOM / STATUS / CHECKOUT_DATE / NEXT_BOOKING / NOTE from the registry tab.
 * NEVER returns EMAIL or any tenant data.
 *  state = 'now'    STATUS VACANT (not under renovation)
 *          'soon'   ACTIVE with CHECKOUT_DATE within AVAIL_WINDOW_DAYS
 *          'reno'   VACANT and NOTE contains ปรับปรุง
 *  until = day before NEXT_BOOKING (if a later booking already exists)
 */
var AVAIL_WINDOW_DAYS = 60;
function availability_() {
  var sh = SpreadsheetApp.openById(P_('REGISTRY_SHEET_ID')).getSheetByName(P_('REGISTRY_TAB', 'LINE_ACCESS'));
  var v = sh.getDataRange().getValues();
  var h = v[0].map(function (x) { return String(x).trim().toUpperCase(); });
  var iR = h.indexOf('ROOM'), iS = h.indexOf('STATUS'), iC = h.indexOf('CHECKOUT_DATE'), iB = h.indexOf('NEXT_BOOKING'), iN = h.indexOf('NOTE');
  var now = new Date(), tz = 'Asia/Bangkok', out = [];
  function d(x) { if (!x) return null; var t = x instanceof Date ? x : new Date(x); return isNaN(t) ? null : t; }
  function fmt(t) { return t ? Utilities.formatDate(t, tz, 'yyyy-MM-dd') : ''; }
  for (var i = 1; i < v.length; i++) {
    var room = GW._normRoom(v[i][iR]); if (!room) continue;
    var status = String(v[i][iS] || '').toUpperCase(), note = iN >= 0 ? String(v[i][iN] || '') : '';
    var co = iC >= 0 ? d(v[i][iC]) : null, nb = iB >= 0 ? d(v[i][iB]) : null;
    var type = room.charAt(0) === 'A' ? 'air' : 'fan';
    var small = room === 'A110' || room === 'A121';
    var until = nb ? new Date(nb.getTime() - 86400e3) : null, rec = null;
    if (status === 'VACANT') rec = { state: /ปรับปรุง/.test(note) ? 'reno' : 'now', from: fmt(now) };
    else if (status === 'ACTIVE' && co && co.getTime() - now.getTime() <= AVAIL_WINDOW_DAYS * 86400e3) rec = { state: 'soon', from: fmt(new Date(co.getTime() + 86400e3)) };   // free from the day after check-out
    if (!rec) continue;
    if (until && rec.from && until.getTime() < new Date(rec.from).getTime()) continue;   // already re-booked from check-out day
    rec.room = room; rec.type = type; rec.small = small; rec.until = fmt(until);
    out.push(rec);
  }
  return { ok: true, asOf: Utilities.formatDate(now, tz, 'yyyy-MM-dd HH:mm'), rooms: out };
}
