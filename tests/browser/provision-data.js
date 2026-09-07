/* tests/browser/provision-data.js — the CONTENT of the design testbed.
 *
 * Kept apart from live-provision.spec.js because the two answer different
 * questions. The spec answers "does the operator's path work"; this file
 * answers "what does the page have to lay out". A design pass re-reads this
 * one, and a reviewer checking that nothing here could be mistaken for a live
 * credential should be able to read it end to end without wading through
 * Playwright.
 *
 * ============================ THE ONE RULE ============================
 *
 * EVERYTHING IN HERE IS SELF-EVIDENTLY FAKE, AND THAT IS A SECURITY
 * PROPERTY, NOT A STYLE PREFERENCE. These safes exist to be screenshotted
 * and shown to people. A fake secret that looks real is a fake secret
 * somebody will one day treat as real — and the reverse failure, a real one
 * that got in here by accident, would be published.
 *
 *   * Every host name is under example.com / example.org / example.net.
 *     RFC 2606 §3 reserves those three precisely so that documentation
 *     cannot collide with anything that resolves.
 *   * Every person is invented (wile.e.coyote, road.runner, barnaby.nobody)
 *     or is a long-dead computing figure the operator named explicitly
 *     (ada.lovelace, grace.hopper). No real living person, no colleague.
 *   * No real company, product, bank, retailer or service. Where the shape
 *     of the thing matters — "this is the sort of entry people keep in a
 *     Personal/Finance group" — the name says so: "Fictional Savings and
 *     Loan", "Imaginary Credit Union", "Pretend Grocery Delivery".
 *   * NO PLAUSIBLE-LOOKING API KEYS OR TOKENS. Where an entry needs a
 *     token-shaped field, the value says what it is in words:
 *     "NOT-A-REAL-TOKEN-example-only". A 32-character base64 blob would be
 *     indistinguishable from the real thing at a glance, and a glance is
 *     all a screenshot gets.
 *   * The TOTP seed is sixteen A's. It generates codes; it protects nothing.
 *
 * ======================= WHY THESE PARTICULAR ROWS ====================
 *
 * A design pass against a tidy safe is worthless, because a tidy safe never
 * happens. Each awkward case below is here because it is a thing the layout
 * has to survive, and every one of them is called out by name in `SPECIALS`
 * at the bottom so a reviewer can check the set is complete rather than
 * counting entries by eye:
 *
 *   a very long title · a title with emoji AND combining marks · a
 *   right-to-left title · an entry with no username · a 300-character URL ·
 *   a 40-line note · one entry with eight tags and one with none ·
 *   protected AND unprotected custom fields on one entry · a TOTP entry ·
 *   two attachments, one tiny and one large · an expired entry · one
 *   expiring in three days · one that never expires · and passwords that
 *   span the strength meter's whole scale, from `password1` to forty
 *   characters of high entropy.
 *
 * The group tree is three levels deep and DELIBERATELY UNEVEN:
 * Infrastructure/Servers is crowded (eight entries) and Personal/Media is
 * empty. Both of those look wrong in a different way when the group rail is
 * badly designed, and a testbed with four entries in every group would
 * show neither.
 */
"use strict";

/* ------------------------------------------------------------ passwords -- */
/* The strength ladder, weakest first. These are fixed strings rather than
 * generated ones so the testbed is REPRODUCIBLE: a design pass that
 * screenshots the meter, and a later run that re-creates the safe, must get
 * the same bars in the same places. Nothing here opens anything. */
const PW = {
    /* very weak — the meter's floor, and the reason the meter exists */
    w1: "password1",
    w2: "letmein2019",
    w3: "qwerty12345",
    /* weak / fair — the shapes people actually choose */
    w4: "Summer2024!",
    w5: "coyote-acme-1949",
    f1: "correct-horse-battery",
    /* strong -> excellent */
    s1: "Hm3$qT8!kV5#zP2%",                              /* 16 */
    s2: "Kp7$vN2!zR9#tL4%wB6^xC",                        /* 22 */
    s3: "Jf4#pQ9!wZ2$nR7%tB6^xL1&yC8*mD3(",              /* 32 */
    s4: "qZ7#vL2$mR9!tK4%wN6^xB1&yC8*zD3(eF5)gH0+"       /* 40 — the ceiling */
};

/* --------------------------------------------------------------- titles -- */
/* ~230 characters, one sentence, no line breaks: the case where a title
 * cannot be wrapped at a punctuation mark and simply has to be dealt with. */
const LONG_TITLE =
    "A deliberately, extravagantly, unreasonably long entry title that exists " +
    "for exactly one reason: so that the safe list, the entry table, the group " +
    "rail and the detail panel can each be judged on what they do with a single " +
    "line of text that refuses to end";

/* Emoji (astral plane, so surrogate pairs) AND combining marks (so the
 * grapheme count and the code-unit count disagree). `String.length` on this
 * is not what a reader would call its length, which is the point. */
const EMOJI_TITLE =
    "🔐📦 Café résumé " +
    "— combining à́̂ ☕🧪";

/* Right-to-left, with a Latin fragment embedded — the mixed case, which is
 * the one that goes wrong. Arabic for "fictional control panel". */
const RTL_TITLE = "لوحة تحكم " +
                  "وهمية — example.org";

/* Exactly 300 characters. Built rather than pasted so the length is a fact
 * the file asserts about itself (see LEN checks in live-provision.spec.js). */
function url300() {
    const head = "https://sw-core-01.example.net/cgi-bin/config?section=interfaces&";
    let s = head;
    let i = 0;
    while (s.length < 300) { s += "vlan" + (100 + (i % 800)) + "=tagged&"; i++; }
    return s.slice(0, 300);
}

/* Exactly 40 lines. A runbook is the honest reason an entry carries one. */
function note40() {
    const lines = [
        "FICTIONAL RUNBOOK — this text is test data and describes nothing real.",
        "",
        "1.  Raise a change ticket with the imaginary change board.",
        "2.  Announce the window on the pretend status page (status.example.org).",
        "3.  Confirm the standby unit at fw-south.example.net is passive.",
        "4.  Take a configuration snapshot and store it beside this entry.",
        "5.  Verify the snapshot is readable before going any further.",
        "6.  Disable the health probe so the pager stays quiet.",
        "7.  Drain sessions from the active unit.",
        "8.  Wait for the session table to reach zero.",
        "9.  Fail over to the standby unit.",
        "10. Confirm the standby is now active.",
        "11. Re-enable the health probe.",
        "12. Watch for five minutes.",
        "13. Upgrade the now-passive unit.",
        "14. Reboot it.",
        "15. Wait for it to rejoin the cluster.",
        "16. Confirm both units report the same configuration revision.",
        "17. Fail back if, and only if, the change ticket asked for it.",
        "18. Re-run the imaginary compliance scan.",
        "19. Attach the scan output to the change ticket.",
        "20. Close the change ticket.",
        "",
        "ROLLBACK",
        "",
        "21. Re-enable the previous configuration revision.",
        "22. Fail over to whichever unit is on the previous revision.",
        "23. Confirm traffic recovers.",
        "24. Leave the health probe disabled until step 27.",
        "25. Collect diagnostics from the failed unit.",
        "26. Raise an incident with the make-believe vendor.",
        "27. Re-enable the health probe.",
        "",
        "NOTES",
        "",
        "This note is forty lines long on purpose. Notes are NOT a protected",
        "field in every format, so nothing secret belongs here — and nothing",
        "secret is here: every host in it is a reserved example.net name and",
        "every procedure is invented.",
        "END OF FICTIONAL RUNBOOK."
    ];
    return lines.join("\n");
}

/* ---------------------------------------------------------------- dates -- */
/* `expires` is an ISO-8601 UTC timestamp, or "" for never. The two relative
 * ones are computed at run time so the testbed keeps meaning what it says: a
 * hard-coded "expires in three days" is expired by the end of the week, and
 * then the page has two expired entries and no soon-to-expire one. */
function iso(dateMs) { return new Date(dateMs).toISOString().replace(/\.\d{3}Z$/, "Z"); }
function daysFromNow(n) { return iso(Date.now() + n * 86400000); }

const EXPIRED = "2019-03-01T00:00:00Z";        /* long past, and it looks it */

/* --------------------------------------------------------- the big safe -- */
/* Group paths, PARENT FIRST — the loader walks this array in order and each
 * entry's parent must already exist. Three levels deep. */
const ADMIN_GROUPS = [
    "Infrastructure",
    "Infrastructure/Servers",
    "Infrastructure/Network",
    "Infrastructure/Network/Switches",
    "Infrastructure/Network/Firewalls",
    "Infrastructure/Storage",
    "Web Services",
    "Web Services/Internal",
    "Web Services/External",
    "Personal",
    "Personal/Finance",
    "Personal/Shopping",
    "Personal/Media",              /* left EMPTY on purpose */
    "Archive",
    "Archive/2019"
];

/* `group: ""` means the root group. */
function adminEntries() {
    return [
        /* ---- Infrastructure/Servers — the CROWDED group (8) -------------- */
        {
            group: "Infrastructure/Servers",
            title: "srv-alpha.example.com — root console",
            username: "wile.e.coyote",
            password: PW.s4,                                  /* 40 chars */
            url: "https://srv-alpha.example.com:9090",
            notes: "Fictional host. Tier-1 in an imaginary datacentre.",
            tags: ["infrastructure", "servers", "linux", "console",
                   "tier-1", "fictional", "review-quarterly", "do-not-use"],
            expires: daysFromNow(400),
            special: "eight tags; the strongest password in the safe"
        },
        {
            group: "Infrastructure/Servers",
            title: "srv-beta.example.com — root console",
            username: "ada.lovelace",
            password: PW.s3,
            url: "https://srv-beta.example.com:9090",
            notes: "Fictional host. No tags at all, deliberately.",
            tags: [],
            expires: "",
            special: "no tags"
        },
        {
            group: "Infrastructure/Servers",
            title: "srv-gamma.example.com — IPMI (shared, no account)",
            username: "",
            password: PW.s2,
            url: "https://ipmi.srv-gamma.example.com/",
            notes: "Fictional out-of-band controller with no per-person account.",
            tags: ["infrastructure", "ipmi"],
            expires: "",
            special: "NO USERNAME"
        },
        {
            group: "Infrastructure/Servers",
            title: "srv-delta.example.com — backup agent",
            username: "grace.hopper",
            password: PW.s1,
            url: "https://srv-delta.example.com:8443",
            notes: "Fictional host. This entry is EXPIRED and should look it.",
            tags: ["infrastructure", "backup"],
            expires: EXPIRED,
            special: "EXPIRED"
        },
        {
            group: "Infrastructure/Servers",
            title: "srv-epsilon.example.com — monitoring",
            username: "barnaby.nobody",
            password: PW.f1,
            url: "https://srv-epsilon.example.com:3000",
            notes: "Fictional host. This entry expires in three days.",
            tags: ["infrastructure", "monitoring"],
            expires: daysFromNow(3),
            special: "EXPIRES IN THREE DAYS"
        },
        {
            group: "Infrastructure/Servers",
            title: "srv-zeta.example.com — legacy telnet",
            username: "road.runner",
            password: PW.w1,                                  /* password1 */
            url: "telnet://srv-zeta.example.com/",
            notes: "Fictional host kept only so the strength meter has a floor.",
            tags: ["infrastructure", "legacy", "do-not-use"],
            expires: "",
            special: "WEAKEST PASSWORD (password1)"
        },
        {
            group: "Infrastructure/Servers",
            title: LONG_TITLE,
            username: "foghorn.leghorn",
            password: PW.w4,
            url: "https://srv-eta.example.com/",
            notes: "Fictional host with an unreasonable title.",
            tags: ["infrastructure"],
            expires: "",
            special: "VERY LONG TITLE"
        },
        {
            group: "Infrastructure/Servers",
            title: "srv-theta.example.com — console with a one-time code",
            username: "wile.e.coyote",
            password: PW.s2,
            url: "https://srv-theta.example.com:9090",
            notes: "Fictional host. The TOTP seed is sixteen A's and protects nothing.",
            tags: ["infrastructure", "mfa"],
            totp_uri: "otpauth://totp/example.com:wile.e.coyote" +
                      "?secret=AAAAAAAAAAAAAAAA&issuer=Example%20Fictional&period=30&digits=6",
            expires: "",
            special: "TOTP"
        },

        /* ---- Infrastructure/Network/Switches (3) ------------------------- */
        {
            group: "Infrastructure/Network/Switches",
            title: "sw-core-01.example.net — web UI",
            username: "netadmin",
            password: PW.s3,
            url: url300(),
            notes: "Fictional switch. The URL is exactly 300 characters.",
            tags: ["network", "switch"],
            expires: "",
            special: "300-CHARACTER URL"
        },
        {
            group: "Infrastructure/Network/Switches",
            title: "sw-edge-02.example.net — web UI",
            username: "netadmin",
            password: PW.s1,
            url: "https://sw-edge-02.example.net/",
            notes: "Fictional switch.",
            tags: ["network", "switch"],
            expires: daysFromNow(210),
            special: null
        },
        {
            group: "Infrastructure/Network/Switches",
            title: "sw-lab-03.example.net — console (never expires)",
            username: "netadmin",
            password: PW.w5,
            url: "https://sw-lab-03.example.net/",
            notes: "Fictional switch. Expiry left empty on purpose: this one NEVER expires.",
            tags: ["network", "switch", "lab"],
            expires: "",
            special: "NEVER EXPIRES (explicit)"
        },

        /* ---- Infrastructure/Network/Firewalls (2) ------------------------ */
        {
            group: "Infrastructure/Network/Firewalls",
            title: "fw-north.example.net — administrator",
            username: "pat.placeholder",
            password: PW.s3,
            url: "https://fw-north.example.net:4443/",
            notes: "Fictional firewall. Carries both protected and unprotected custom fields.",
            tags: ["network", "firewall"],
            expires: daysFromNow(90),
            custom: {
                "Fictional support PIN":
                    { value: "0000-not-a-real-pin", protected: true },
                "Pretend recovery phrase":
                    { value: "this string is not a real recovery phrase", protected: true },
                "Rack location (not a secret)":
                    { value: "Row 0, Rack 0, imaginary datacentre", protected: false },
                "Made-up ticket reference":
                    { value: "TICKET-000000-FAKE", protected: false }
            },
            special: "PROTECTED AND UNPROTECTED CUSTOM FIELDS"
        },
        {
            group: "Infrastructure/Network/Firewalls",
            title: "fw-south.example.net — administrator",
            username: "pat.placeholder",
            password: PW.s2,
            url: "https://fw-south.example.net:4443/",
            notes: note40(),
            tags: ["network", "firewall", "runbook"],
            expires: daysFromNow(90),
            special: "40-LINE NOTE"
        },

        /* ---- Infrastructure/Storage (3) ---------------------------------- */
        {
            group: "Infrastructure/Storage",
            title: "nas-01.example.com — array console",
            username: "jane.doe",
            password: PW.s1,
            url: "https://nas-01.example.com/",
            notes: "Fictional array. Carries the TINY attachment.",
            tags: ["storage"],
            expires: "",
            attach: "tiny",
            special: "TINY ATTACHMENT"
        },
        {
            group: "Infrastructure/Storage",
            title: "nas-02.example.com — array console",
            username: "john.doe",
            password: PW.s2,
            url: "https://nas-02.example.com/",
            notes: "Fictional array. Carries the LARGE attachment.",
            tags: ["storage"],
            expires: "",
            attach: "large",
            special: "LARGE ATTACHMENT"
        },
        {
            group: "Infrastructure/Storage",
            title: "tape-robot.example.org — service account",
            username: "svc-tape",
            password: PW.f1,
            url: "",
            notes: "Fictional tape library. No URL, on purpose.",
            tags: ["storage", "service-account"],
            expires: "",
            special: null
        },

        /* ---- Web Services/Internal (3) ----------------------------------- */
        {
            group: "Web Services/Internal",
            title: "wiki.internal.example.com — editor",
            username: "hermione.fictional",
            password: PW.w4,
            url: "https://wiki.internal.example.com/",
            notes: "Fictional internal wiki.",
            tags: ["web", "internal"],
            expires: "",
            special: null
        },
        {
            group: "Web Services/Internal",
            title: "ci.internal.example.com — build robot",
            username: "svc-build",
            password: PW.s3,
            url: "https://ci.internal.example.com/",
            notes: "Fictional build server.",
            tags: ["web", "internal", "ci"],
            expires: daysFromNow(30),
            custom: {
                "Made-up build token (NOT a credential)":
                    { value: "NOT-A-REAL-TOKEN-example-only", protected: true }
            },
            special: null
        },
        {
            group: "Web Services/Internal",
            title: EMOJI_TITLE,
            username: "sam.sample",
            password: PW.s1,
            url: "https://cafe.internal.example.com/",
            notes: "Fictional entry whose title carries emoji and combining marks.",
            tags: ["web", "internal", "unicode"],
            expires: "",
            special: "EMOJI + COMBINING MARKS TITLE"
        },

        /* ---- Web Services/External (3) ----------------------------------- */
        {
            group: "Web Services/External",
            title: "status.example.org — publisher",
            username: "svc-status",
            password: PW.s2,
            url: "https://status.example.org/admin",
            notes: "Fictional public status page.",
            tags: ["web", "external"],
            expires: daysFromNow(150),
            special: null
        },
        {
            group: "Web Services/External",
            title: RTL_TITLE,
            username: "nemo.nobody",
            password: PW.s1,
            url: "https://rtl.example.org/",
            notes: "Fictional entry with a right-to-left title.",
            tags: ["web", "external", "unicode"],
            expires: "",
            special: "RIGHT-TO-LEFT TITLE"
        },
        {
            group: "Web Services/External",
            title: "shop.example.net — storefront administrator",
            username: "sam.sample",
            password: PW.w3,
            url: "https://shop.example.net/admin",
            notes: "Fictional storefront.",
            tags: ["web", "external"],
            expires: "",
            special: null
        },

        /* ---- Personal/Finance (3) ---------------------------------------- */
        {
            group: "Personal/Finance",
            title: "Fictional Savings and Loan (example.com) — online banking",
            username: "barnaby.nobody",
            password: PW.s4,
            url: "https://bank.example.com/login",
            notes: "There is no such institution. This entry is shaped like a bank " +
                   "login so the layout can be judged; it opens nothing.",
            tags: ["personal", "finance"],
            expires: "",
            special: null
        },
        {
            group: "Personal/Finance",
            title: "Imaginary Credit Union (example.org) — card portal",
            username: "barnaby.nobody",
            password: PW.s3,
            url: "https://cards.example.org/",
            notes: "There is no such institution.",
            tags: ["personal", "finance"],
            expires: daysFromNow(60),
            special: null
        },
        {
            group: "Personal/Finance",
            title: "Make-Believe Pension Fund (example.net) — member login",
            username: "barnaby.nobody",
            password: PW.w2,
            url: "https://pension.example.net/",
            notes: "There is no such institution.",
            tags: ["personal", "finance"],
            expires: "",
            special: null
        },

        /* ---- Personal/Shopping (2) --------------------------------------- */
        {
            group: "Personal/Shopping",
            title: "Nonexistent Bookshop (example.com)",
            username: "barnaby.nobody",
            password: PW.w4,
            url: "https://books.example.com/account",
            notes: "There is no such shop.",
            tags: ["personal", "shopping"],
            expires: "",
            special: null
        },
        {
            group: "Personal/Shopping",
            title: "Pretend Grocery Delivery (example.org)",
            username: "barnaby.nobody",
            password: PW.f1,
            url: "https://groceries.example.org/account",
            notes: "There is no such shop.",
            tags: ["personal", "shopping"],
            expires: "",
            special: null
        },

        /* ---- Personal/Media: DELIBERATELY EMPTY -------------------------- */

        /* ---- Archive/2019 (3) -------------------------------------------- */
        {
            group: "Archive/2019",
            title: "old-mail.example.com — IMAP (retired 2019)",
            username: "barnaby.nobody",
            password: PW.w2,
            url: "imap://old-mail.example.com/",
            notes: "Fictional retired service.",
            tags: ["archive", "retired"],
            expires: EXPIRED,
            special: null
        },
        {
            group: "Archive/2019",
            title: "old-vpn.example.net — dial-in (retired 2019)",
            username: "barnaby.nobody",
            password: PW.w3,
            url: "https://old-vpn.example.net/",
            notes: "Fictional retired service.",
            tags: ["archive", "retired"],
            expires: EXPIRED,
            special: null
        },
        {
            group: "Archive/2019",
            title: "old-crm.example.org — retired application",
            username: "svc-crm",
            password: PW.w5,
            url: "https://old-crm.example.org/",
            notes: "Fictional retired service.",
            tags: ["archive", "retired"],
            expires: EXPIRED,
            special: null
        },

        /* ---- the root group (1) ------------------------------------------ */
        {
            group: "",
            title: "Front desk shared login (fictional, do not use)",
            username: "frontdesk",
            password: PW.w3,
            url: "https://frontdesk.example.com/",
            notes: "Fictional shared account, kept at the root of the safe so the " +
                   "root group is not empty.",
            tags: ["shared"],
            expires: "",
            special: "lives in the ROOT group"
        }
    ];
}

/* Created at the root, then `rm`'d WITHOUT `permanent`, which moves it to the
 * recycle bin. The bin has to have something in it or the page's handling of
 * it is untested. */
const ADMIN_RECYCLED = {
    group: "",
    title: "Deleted fictional account (example.com)",
    username: "ex.employee",
    password: PW.w1,
    url: "https://gone.example.com/",
    notes: "Created and then deleted so the recycle bin is not empty.",
    tags: ["deleted"],
    expires: ""
};

/* --------------------------------------------------------- attachments --- */
/* THE LARGE ONE IS 720 000 BYTES, NOT 1 MiB, AND THE NUMBER IS NOT ARBITRARY.
 *
 * The helper caps a whole request — session frame included — at
 * `constants.max_request_bytes`, which is 1 MiB on this host, and an
 * attachment travels base64-encoded inside that JSON object. Base64 costs
 * 4 bytes per 3, so 1 MiB of frame holds about 768 KiB of file and the
 * schema's own `breaks_when_wrong` for `data_b64` says so. 720 000 bytes
 * encodes to 960 000 and leaves ~88 KiB of headroom for the envelope.
 *
 * A 1 048 576-byte attachment would be refused, and "the testbed asked for
 * something the transport cannot carry" is a worse outcome than a file that
 * is 0.7 MB instead of 1 MB. It is still three orders of magnitude larger
 * than the tiny one, which is what the layout is being asked about. */
const ATTACH = {
    tiny: {
        name: "fictional-serial-numbers.txt",
        text: "FAKE TEST DATA. Array serial: SN-000000-FICTIONAL.\n" +
              "Nothing in this file is real.\n"
    },
    large: {
        name: "fictional-topology-export.txt",
        bytes: 720000,
        /* Repeated to fill `bytes`; every line says what it is. */
        chunk: "FAKE TEST DATA FOR cockpit-secrets - this export describes " +
               "nothing real and contains no credential.\n"
    }
};

/* ------------------------------------------------- the user-class KDBX --- */
const USER_KDBX_GROUPS = ["Work", "Work/Accounts", "Work/Servers", "Home"];

function userKdbxEntries() {
    return [
        {
            group: "Work/Accounts",
            title: "helpdesk.example.com — agent login",
            username: "sam.sample",
            password: PW.s2,
            url: "https://helpdesk.example.com/",
            notes: "Fictional helpdesk.",
            tags: ["work", "helpdesk"],
            expires: ""
        },
        {
            group: "Work/Accounts",
            title: "timesheets.example.org — self service",
            username: "sam.sample",
            password: PW.w4,
            url: "https://timesheets.example.org/",
            notes: "Fictional timesheet system.",
            tags: [],
            expires: EXPIRED,
            special: "EXPIRED, in the smaller user-class safe"
        },
        {
            group: "Work/Servers",
            title: "build-01.example.com — shell",
            username: "ada.lovelace",
            password: PW.s4,
            url: "ssh://build-01.example.com/",
            notes: "Fictional build host.",
            tags: ["work", "servers", "ssh"],
            expires: daysFromNow(3),
            special: "EXPIRES IN THREE DAYS, user class"
        },
        {
            group: "Work/Servers",
            title: "build-02.example.com — shell (one-time code)",
            username: "ada.lovelace",
            password: PW.s3,
            url: "ssh://build-02.example.com/",
            notes: "Fictional build host. The TOTP seed is sixteen A's.",
            tags: ["work", "servers", "mfa"],
            totp_uri: "otpauth://totp/example.com:ada.lovelace" +
                      "?secret=AAAAAAAAAAAAAAAA&issuer=Example%20Fictional&period=30&digits=6",
            expires: "",
            special: "TOTP, user class"
        },
        {
            group: "Home",
            title: "router.home.example.net — admin",
            username: "",
            password: PW.w1,
            url: "http://router.home.example.net/",
            notes: "Fictional home router with no account name.",
            tags: ["home"],
            expires: "",
            special: "no username, user class"
        },
        {
            group: "Home",
            title: "Pretend Streaming Service (example.org)",
            username: "barnaby.nobody",
            password: PW.f1,
            url: "https://stream.example.org/",
            notes: "There is no such service.",
            tags: ["home", "media"],
            expires: "",
            custom: {
                "Household note (not a secret)":
                    { value: "shared with the imaginary family", protected: false }
            }
        },
        {
            group: "",
            title: "Personal notes (no password at all)",
            username: "barnaby.nobody",
            password: "",
            url: "",
            notes: "An entry with no password, so the meter has an empty case to draw.",
            tags: [],
            expires: "",
            special: "NO PASSWORD"
        }
    ];
}

/* ------------------------------------------------ the user-class PWS3 ---- */
/* SMALLER, AND NARROWER, BECAUSE THE FORMAT IS.
 *
 * Password Safe v3 answers `unsupported` for tags (§3.3 lists no tag field)
 * and for custom fields (a record is a list of TYPED fields, each type once,
 * so there is no name-keyed space to create one in), and a safe this program
 * CREATES declares format 0x030D, below the 0x030F that introduced
 * attachments. None of that is a gap in the helper — it is the format — and
 * a testbed that sent them anyway would fill the report with refusals that
 * say nothing about the page. What it DOES carry is the warning state the
 * design pass needs: the page shows those limits on the safe itself. */
const USER_PSAFE3_GROUPS = ["Legacy", "Legacy/Routers", "Legacy/Modems"];

function userPsafe3Entries() {
    return [
        {
            group: "Legacy/Routers",
            title: "rtr-old-01.example.net — enable",
            username: "netadmin",
            password: PW.s1,
            url: "telnet://rtr-old-01.example.net/",
            notes: "Fictional retired router.",
            expires: ""
        },
        {
            group: "Legacy/Routers",
            title: "rtr-old-02.example.net — enable",
            username: "netadmin",
            password: PW.w2,
            url: "telnet://rtr-old-02.example.net/",
            notes: "Fictional retired router.",
            expires: EXPIRED,
            special: "EXPIRED, PWS3"
        },
        {
            group: "Legacy/Modems",
            title: "modem-bank.example.org — console",
            username: "",
            password: PW.w5,
            url: "",
            notes: note40(),
            expires: "",
            special: "no username AND a 40-line note, PWS3"
        },
        {
            group: "Legacy",
            title: "Ancient billing system (example.com)",
            username: "svc-billing",
            password: PW.s3,
            url: "https://billing.example.com/",
            notes: "Fictional retired application.",
            expires: daysFromNow(3),
            special: "EXPIRES IN THREE DAYS, PWS3"
        },
        {
            group: "",
            title: "Dial-in shared account (fictional)",
            username: "dialin",
            password: PW.w1,
            url: "",
            notes: "Fictional. Root group of the PWS3 safe.",
            expires: "",
            special: "weakest password, PWS3"
        }
    ];
}

/* ------------------------------------------------------------- specials -- */
/* The checklist the spec asserts against, so "every awkward case is present"
 * is a test result and not a claim. Each key names a case the task asked
 * for; each value is the predicate that finds it in `adminEntries()` (plus
 * the two extras that are not entry fields). */
const SPECIALS = [
    "eight tags; the strongest password in the safe",
    "no tags",
    "NO USERNAME",
    "EXPIRED",
    "EXPIRES IN THREE DAYS",
    "WEAKEST PASSWORD (password1)",
    "VERY LONG TITLE",
    "TOTP",
    "300-CHARACTER URL",
    "NEVER EXPIRES (explicit)",
    "PROTECTED AND UNPROTECTED CUSTOM FIELDS",
    "40-LINE NOTE",
    "TINY ATTACHMENT",
    "LARGE ATTACHMENT",
    "EMOJI + COMBINING MARKS TITLE",
    "RIGHT-TO-LEFT TITLE",
    "lives in the ROOT group"
];

module.exports = {
    PW, LONG_TITLE, EMOJI_TITLE, RTL_TITLE, url300, note40,
    EXPIRED, daysFromNow, iso,
    ADMIN_GROUPS, adminEntries, ADMIN_RECYCLED, ATTACH,
    USER_KDBX_GROUPS, userKdbxEntries,
    USER_PSAFE3_GROUPS, userPsafe3Entries,
    SPECIALS
};
