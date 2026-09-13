// Metamorphic testing of Temporal, with the unsound oracles removed.
//
// The first version reported 3618 "violations". Every one was my invariant
// being wrong, not V8. Recorded here so the mistakes are not repeated:
//
//   add/subtract inverse   NOT an invariant. Calendar months clamp:
//                          2000-01-31 +1M = 2000-02-29, -1M = 2000-01-29.
//   compare vs until sign  Backwards. compare(a,b) is -1 when a<b, while
//                          a.until(b) is positive when b>a, so the signs are
//                          opposite by definition.
//   total negation         NOT an invariant with a calendar anchor. Walking 14
//                          months back from a date spans a different number of
//                          days than walking 14 months forward.
//   until/since symmetry   Not sound with calendar largestUnits, because the
//                          two calls balance against different anchors. Kept
//                          below restricted to days, where no balancing occurs.
//
// What remains are relations that hold by construction.

let checks = 0, fails = 0;
const seen = new Set();

function fail(rule, detail) {
  const key = rule + "|" + detail;
  if (seen.has(key)) return;
  seen.add(key);
  fails++;
  if (seen.size <= 40) print("VIOLATION [" + rule + "] " + detail);
}

function check(rule, cond, detail) {
  checks++;
  if (!cond) fail(rule, detail);
}

let S = 0x2f6e2b1;
function rnd(n) {
  S ^= S << 13; S >>>= 0; S ^= S >> 17; S ^= S << 5; S >>>= 0;
  return S % n;
}

const DATES = [];
for (let y of [1, 1000, 1969, 1970, 1999, 2000, 2023, 2024, 2025, 2100, 9999]) {
  for (let m of [1, 2, 3, 6, 12]) {
    for (let d of [1, 15, 28, 29, 30, 31]) {
      try { DATES.push(Temporal.PlainDate.from({year: y, month: m, day: d})); }
      catch (e) {}
    }
  }
}

const UNITS = ["years", "months", "weeks", "days", "hours", "minutes",
               "seconds", "milliseconds", "microseconds", "nanoseconds"];

function randDuration(maxFields) {
  const f = {};
  const n = 1 + rnd(maxFields);
  for (let i = 0; i < n; i++) f[UNITS[rnd(UNITS.length)]] = rnd(40) - 20;
  try { return Temporal.Duration.from(f); } catch (e) { return null; }
}

// 1. a.until(b) applied to a lands exactly on b. Sound for any largestUnit:
//    the duration is computed relative to a and then added back to a.
for (let i = 0; i < 6000; i++) {
  const a = DATES[rnd(DATES.length)], b = DATES[rnd(DATES.length)];
  const lu = UNITS[rnd(4)];
  let dur, landed;
  try { dur = a.until(b, {largestUnit: lu}); landed = a.add(dur); }
  catch (e) { continue; }
  check("until/add round trip", landed.equals(b),
        a.toString() + " until " + b.toString() + " (" + lu + ") = " +
        dur.toString() + " -> lands on " + landed.toString());
}

// 2. b.since(a) applied to b in reverse lands exactly on a. Mirror of 1.
for (let i = 0; i < 6000; i++) {
  const a = DATES[rnd(DATES.length)], b = DATES[rnd(DATES.length)];
  const lu = UNITS[rnd(4)];
  let dur, landed;
  try { dur = b.since(a, {largestUnit: lu}); landed = b.subtract(dur); }
  catch (e) { continue; }
  check("since/subtract round trip", landed.equals(a),
        b.toString() + " since " + a.toString() + " (" + lu + ") = " +
        dur.toString() + " -> lands on " + landed.toString());
}

// 3. In days there is no calendar balancing, so until and since must agree.
for (let i = 0; i < 4000; i++) {
  const a = DATES[rnd(DATES.length)], b = DATES[rnd(DATES.length)];
  let u, s;
  try {
    u = a.until(b, {largestUnit: "days"});
    s = b.since(a, {largestUnit: "days"});
  } catch (e) { continue; }
  check("until/since agree in days", u.days === s.days,
        a.toString() + " vs " + b.toString() + ": until=" + u.days +
        " since=" + s.days);
}

// 4. compare is consistent with the sign of until, with the right convention.
for (let i = 0; i < 4000; i++) {
  const a = DATES[rnd(DATES.length)], b = DATES[rnd(DATES.length)];
  const cmp = Temporal.PlainDate.compare(a, b);
  let days;
  try { days = a.until(b, {largestUnit: "days"}).days; } catch (e) { continue; }
  const expect = days === 0 ? 0 : (days > 0 ? -1 : 1);
  check("compare vs until sign", cmp === expect,
        a.toString() + " vs " + b.toString() + ": compare=" + cmp +
        " until.days=" + days);
}

// 5. toString then from is the identity.
for (let i = 0; i < 4000; i++) {
  const d = DATES[rnd(DATES.length)], dur = randDuration(3);
  if (!dur) continue;
  let x, rt;
  try { x = d.add(dur); rt = Temporal.PlainDate.from(x.toString()); }
  catch (e) { continue; }
  check("date string round trip", rt.equals(x),
        x.toString() + " reparsed as " + rt.toString());
}

// 6. Duration round is idempotent at a fixed smallestUnit and anchor.
for (let i = 0; i < 4000; i++) {
  const dur = randDuration(4);
  if (!dur) continue;
  const rel = DATES[rnd(DATES.length)], su = UNITS[rnd(UNITS.length)];
  let a, b;
  try {
    a = dur.round({smallestUnit: su, relativeTo: rel});
    b = a.round({smallestUnit: su, relativeTo: rel});
  } catch (e) { continue; }
  check("round idempotent", a.toString() === b.toString(),
        dur.toString() + " round(" + su + ") = " + a.toString() +
        " then " + b.toString());
}

// 7. Duration string round trip.
for (let i = 0; i < 5000; i++) {
  const dur = randDuration(5);
  if (!dur) continue;
  let rt;
  try { rt = Temporal.Duration.from(dur.toString()); }
  catch (e) { fail("duration string round trip", dur.toString() + " -> " + e); continue; }
  check("duration string round trip", rt.toString() === dur.toString(),
        dur.toString() + " reparsed as " + rt.toString());
}

// 8. A duration negated twice is the original.
for (let i = 0; i < 4000; i++) {
  const dur = randDuration(5);
  if (!dur) continue;
  check("double negation", dur.negated().negated().toString() === dur.toString(),
        dur.toString() + " -> " + dur.negated().negated().toString());
}

// 9. abs is negation-invariant and non-negative.
for (let i = 0; i < 4000; i++) {
  const dur = randDuration(5);
  if (!dur) continue;
  check("abs invariant",
        dur.abs().toString() === dur.negated().abs().toString() && dur.abs().sign >= 0,
        dur.toString() + " abs=" + dur.abs().toString() +
        " negated abs=" + dur.negated().abs().toString());
}

// 10. PlainDateTime agrees with its parts; year/month/day views agree.
for (let i = 0; i < 4000; i++) {
  const d = DATES[rnd(DATES.length)];
  const h = rnd(24), mi = rnd(60);
  let dt, ym, md;
  try {
    dt = d.toPlainDateTime(Temporal.PlainTime.from({hour: h, minute: mi}));
    ym = d.toPlainYearMonth();
    md = d.toPlainMonthDay();
  } catch (e) { continue; }
  check("datetime decomposition",
        dt.toPlainDate().equals(d) && dt.hour === h && dt.minute === mi,
        dt.toString());
  check("yearmonth agreement",
        ym.year === d.year && ym.month === d.month && ym.daysInMonth === d.daysInMonth,
        d.toString() + " -> " + ym.toString());
  check("monthday agreement", md.monthCode === d.monthCode && md.day === d.day,
        d.toString() + " -> " + md.toString());
}

// 11. dayOfWeek advances by one per day, wrapping 7 -> 1.
for (let i = 0; i < 4000; i++) {
  const d = DATES[rnd(DATES.length)];
  let n;
  try { n = d.add({days: 1}); } catch (e) { continue; }
  const want = d.dayOfWeek === 7 ? 1 : d.dayOfWeek + 1;
  check("dayOfWeek monotone", n.dayOfWeek === want,
        d.toString() + " dow=" + d.dayOfWeek + " next=" + n.toString() +
        " dow=" + n.dayOfWeek);
}

// 12. dayOfYear and daysInYear are consistent.
for (let i = 0; i < 4000; i++) {
  const d = DATES[rnd(DATES.length)];
  check("dayOfYear in range", d.dayOfYear >= 1 && d.dayOfYear <= d.daysInYear,
        d.toString() + " dayOfYear=" + d.dayOfYear + " daysInYear=" + d.daysInYear);
  const jan1 = Temporal.PlainDate.from({year: d.year, month: 1, day: 1});
  let back;
  try { back = jan1.add({days: d.dayOfYear - 1}); } catch (e) { continue; }
  check("dayOfYear reconstructs", back.equals(d),
        d.toString() + " dayOfYear=" + d.dayOfYear + " reconstructs to " + back.toString());
}

print("checks=" + checks + " violations=" + fails + " distinct=" + seen.size);
