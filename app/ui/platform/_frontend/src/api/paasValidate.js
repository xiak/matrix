// Generated from api/paas/v1/openapi.json. Run npm run generate:contracts.
var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

// node_modules/ajv-formats/dist/formats.js
var require_formats = __commonJS({
  "node_modules/ajv-formats/dist/formats.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.formatNames = exports.fastFormats = exports.fullFormats = void 0;
    function fmtDef(validate, compare) {
      return { validate, compare };
    }
    exports.fullFormats = {
      // date: http://tools.ietf.org/html/rfc3339#section-5.6
      date: fmtDef(date, compareDate),
      // date-time: http://tools.ietf.org/html/rfc3339#section-5.6
      time: fmtDef(getTime(true), compareTime),
      "date-time": fmtDef(getDateTime(true), compareDateTime),
      "iso-time": fmtDef(getTime(), compareIsoTime),
      "iso-date-time": fmtDef(getDateTime(), compareIsoDateTime),
      // duration: https://tools.ietf.org/html/rfc3339#appendix-A
      duration: /^P(?!$)((\d+Y)?(\d+M)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?|(\d+W)?)$/,
      uri,
      "uri-reference": /^(?:[a-z][a-z0-9+\-.]*:)?(?:\/?\/(?:(?:[a-z0-9\-._~!$&'()*+,;=:]|%[0-9a-f]{2})*@)?(?:\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\.[a-z0-9\-._~!$&'()*+,;=:]+)\]|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|(?:[a-z0-9\-._~!$&'"()*+,;=]|%[0-9a-f]{2})*)(?::\d*)?(?:\/(?:[a-z0-9\-._~!$&'"()*+,;=:@]|%[0-9a-f]{2})*)*|\/(?:(?:[a-z0-9\-._~!$&'"()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'"()*+,;=:@]|%[0-9a-f]{2})*)*)?|(?:[a-z0-9\-._~!$&'"()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'"()*+,;=:@]|%[0-9a-f]{2})*)*)?(?:\?(?:[a-z0-9\-._~!$&'"()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\-._~!$&'"()*+,;=:@/?]|%[0-9a-f]{2})*)?$/i,
      // uri-template: https://tools.ietf.org/html/rfc6570
      "uri-template": /^(?:(?:[^\x00-\x20"'<>%\\^`{|}]|%[0-9a-f]{2})|\{[+#./;?&=,!@|]?(?:[a-z0-9_]|%[0-9a-f]{2})+(?::[1-9][0-9]{0,3}|\*)?(?:,(?:[a-z0-9_]|%[0-9a-f]{2})+(?::[1-9][0-9]{0,3}|\*)?)*\})*$/i,
      // For the source: https://gist.github.com/dperini/729294
      // For test cases: https://mathiasbynens.be/demo/url-regex
      url: /^(?:https?|ftp):\/\/(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\u{00a1}-\u{ffff}]+-)*[a-z0-9\u{00a1}-\u{ffff}]+)(?:\.(?:[a-z0-9\u{00a1}-\u{ffff}]+-)*[a-z0-9\u{00a1}-\u{ffff}]+)*(?:\.(?:[a-z\u{00a1}-\u{ffff}]{2,})))(?::\d{2,5})?(?:\/[^\s]*)?$/iu,
      email: /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i,
      hostname: /^(?=.{1,253}\.?$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-0-9a-z]{0,61}[0-9a-z])?)*\.?$/i,
      // optimized https://www.safaribooksonline.com/library/view/regular-expressions-cookbook/9780596802837/ch07s16.html
      ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/,
      ipv6: /^((([0-9a-f]{1,4}:){7}([0-9a-f]{1,4}|:))|(([0-9a-f]{1,4}:){6}(:[0-9a-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){5}(((:[0-9a-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9a-f]{1,4}:){4}(((:[0-9a-f]{1,4}){1,3})|((:[0-9a-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){3}(((:[0-9a-f]{1,4}){1,4})|((:[0-9a-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){2}(((:[0-9a-f]{1,4}){1,5})|((:[0-9a-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9a-f]{1,4}:){1}(((:[0-9a-f]{1,4}){1,6})|((:[0-9a-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9a-f]{1,4}){1,7})|((:[0-9a-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))$/i,
      regex,
      // uuid: http://tools.ietf.org/html/rfc4122
      uuid: /^(?:urn:uuid:)?[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i,
      // JSON-pointer: https://tools.ietf.org/html/rfc6901
      // uri fragment: https://tools.ietf.org/html/rfc3986#appendix-A
      "json-pointer": /^(?:\/(?:[^~/]|~0|~1)*)*$/,
      "json-pointer-uri-fragment": /^#(?:\/(?:[a-z0-9_\-.!$&'()*+,;:=@]|%[0-9a-f]{2}|~0|~1)*)*$/i,
      // relative JSON-pointer: http://tools.ietf.org/html/draft-luff-relative-json-pointer-00
      "relative-json-pointer": /^(?:0|[1-9][0-9]*)(?:#|(?:\/(?:[^~/]|~0|~1)*)*)$/,
      // the following formats are used by the openapi specification: https://spec.openapis.org/oas/v3.0.0#data-types
      // byte: https://github.com/miguelmota/is-base64
      byte,
      // signed 32 bit integer
      int32: { type: "number", validate: validateInt32 },
      // signed 64 bit integer
      int64: { type: "number", validate: validateInt64 },
      // C-type float
      float: { type: "number", validate: validateNumber },
      // C-type double
      double: { type: "number", validate: validateNumber },
      // hint to the UI to hide input strings
      password: true,
      // unchecked string payload
      binary: true
    };
    exports.fastFormats = {
      ...exports.fullFormats,
      date: fmtDef(/^\d\d\d\d-[0-1]\d-[0-3]\d$/, compareDate),
      time: fmtDef(/^(?:[0-2]\d:[0-5]\d:[0-5]\d|23:59:60)(?:\.\d+)?(?:z|[+-]\d\d(?::?\d\d)?)$/i, compareTime),
      "date-time": fmtDef(/^\d\d\d\d-[0-1]\d-[0-3]\dt(?:[0-2]\d:[0-5]\d:[0-5]\d|23:59:60)(?:\.\d+)?(?:z|[+-]\d\d(?::?\d\d)?)$/i, compareDateTime),
      "iso-time": fmtDef(/^(?:[0-2]\d:[0-5]\d:[0-5]\d|23:59:60)(?:\.\d+)?(?:z|[+-]\d\d(?::?\d\d)?)?$/i, compareIsoTime),
      "iso-date-time": fmtDef(/^\d\d\d\d-[0-1]\d-[0-3]\d[t\s](?:[0-2]\d:[0-5]\d:[0-5]\d|23:59:60)(?:\.\d+)?(?:z|[+-]\d\d(?::?\d\d)?)?$/i, compareIsoDateTime),
      // uri: https://github.com/mafintosh/is-my-json-valid/blob/master/formats.js
      uri: /^(?:[a-z][a-z0-9+\-.]*:)(?:\/?\/)?[^\s]*$/i,
      "uri-reference": /^(?:(?:[a-z][a-z0-9+\-.]*:)?\/?\/)?(?:[^\\\s#][^\s#]*)?(?:#[^\\\s]*)?$/i,
      // email (sources from jsen validator):
      // http://stackoverflow.com/questions/201323/using-a-regular-expression-to-validate-an-email-address#answer-8829363
      // http://www.w3.org/TR/html5/forms.html#valid-e-mail-address (search for 'wilful violation')
      email: /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i
    };
    exports.formatNames = Object.keys(exports.fullFormats);
    function isLeapYear(year) {
      return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    }
    var DATE = /^(\d\d\d\d)-(\d\d)-(\d\d)$/;
    var DAYS = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    function date(str) {
      const matches = DATE.exec(str);
      if (!matches)
        return false;
      const year = +matches[1];
      const month = +matches[2];
      const day = +matches[3];
      return month >= 1 && month <= 12 && day >= 1 && day <= (month === 2 && isLeapYear(year) ? 29 : DAYS[month]);
    }
    function compareDate(d1, d2) {
      if (!(d1 && d2))
        return void 0;
      if (d1 > d2)
        return 1;
      if (d1 < d2)
        return -1;
      return 0;
    }
    var TIME = /^(\d\d):(\d\d):(\d\d(?:\.\d+)?)(z|([+-])(\d\d)(?::?(\d\d))?)?$/i;
    function getTime(strictTimeZone) {
      return function time(str) {
        const matches = TIME.exec(str);
        if (!matches)
          return false;
        const hr = +matches[1];
        const min = +matches[2];
        const sec = +matches[3];
        const tz = matches[4];
        const tzSign = matches[5] === "-" ? -1 : 1;
        const tzH = +(matches[6] || 0);
        const tzM = +(matches[7] || 0);
        if (tzH > 23 || tzM > 59 || strictTimeZone && !tz)
          return false;
        if (hr <= 23 && min <= 59 && sec < 60)
          return true;
        const utcMin = min - tzM * tzSign;
        const utcHr = hr - tzH * tzSign - (utcMin < 0 ? 1 : 0);
        return (utcHr === 23 || utcHr === -1) && (utcMin === 59 || utcMin === -1) && sec < 61;
      };
    }
    function compareTime(s1, s2) {
      if (!(s1 && s2))
        return void 0;
      const t1 = (/* @__PURE__ */ new Date("2020-01-01T" + s1)).valueOf();
      const t2 = (/* @__PURE__ */ new Date("2020-01-01T" + s2)).valueOf();
      if (!(t1 && t2))
        return void 0;
      return t1 - t2;
    }
    function compareIsoTime(t1, t2) {
      if (!(t1 && t2))
        return void 0;
      const a1 = TIME.exec(t1);
      const a2 = TIME.exec(t2);
      if (!(a1 && a2))
        return void 0;
      t1 = a1[1] + a1[2] + a1[3];
      t2 = a2[1] + a2[2] + a2[3];
      if (t1 > t2)
        return 1;
      if (t1 < t2)
        return -1;
      return 0;
    }
    var DATE_TIME_SEPARATOR = /t|\s/i;
    function getDateTime(strictTimeZone) {
      const time = getTime(strictTimeZone);
      return function date_time(str) {
        const dateTime = str.split(DATE_TIME_SEPARATOR);
        return dateTime.length === 2 && date(dateTime[0]) && time(dateTime[1]);
      };
    }
    function compareDateTime(dt1, dt2) {
      if (!(dt1 && dt2))
        return void 0;
      const d1 = new Date(dt1).valueOf();
      const d2 = new Date(dt2).valueOf();
      if (!(d1 && d2))
        return void 0;
      return d1 - d2;
    }
    function compareIsoDateTime(dt1, dt2) {
      if (!(dt1 && dt2))
        return void 0;
      const [d1, t1] = dt1.split(DATE_TIME_SEPARATOR);
      const [d2, t2] = dt2.split(DATE_TIME_SEPARATOR);
      const res = compareDate(d1, d2);
      if (res === void 0)
        return void 0;
      return res || compareTime(t1, t2);
    }
    var NOT_URI_FRAGMENT = /\/|:/;
    var URI = /^(?:[a-z][a-z0-9+\-.]*:)(?:\/?\/(?:(?:[a-z0-9\-._~!$&'()*+,;=:]|%[0-9a-f]{2})*@)?(?:\[(?:(?:(?:(?:[0-9a-f]{1,4}:){6}|::(?:[0-9a-f]{1,4}:){5}|(?:[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){4}|(?:(?:[0-9a-f]{1,4}:){0,1}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){3}|(?:(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4})?::(?:[0-9a-f]{1,4}:){2}|(?:(?:[0-9a-f]{1,4}:){0,3}[0-9a-f]{1,4})?::[0-9a-f]{1,4}:|(?:(?:[0-9a-f]{1,4}:){0,4}[0-9a-f]{1,4})?::)(?:[0-9a-f]{1,4}:[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))|(?:(?:[0-9a-f]{1,4}:){0,5}[0-9a-f]{1,4})?::[0-9a-f]{1,4}|(?:(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4})?::)|[Vv][0-9a-f]+\.[a-z0-9\-._~!$&'()*+,;=:]+)\]|(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)|(?:[a-z0-9\-._~!$&'()*+,;=]|%[0-9a-f]{2})*)(?::\d*)?(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*|\/(?:(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)?|(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})+(?:\/(?:[a-z0-9\-._~!$&'()*+,;=:@]|%[0-9a-f]{2})*)*)(?:\?(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?(?:#(?:[a-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9a-f]{2})*)?$/i;
    function uri(str) {
      return NOT_URI_FRAGMENT.test(str) && URI.test(str);
    }
    var BYTE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/gm;
    function byte(str) {
      BYTE.lastIndex = 0;
      return BYTE.test(str);
    }
    var MIN_INT32 = -(2 ** 31);
    var MAX_INT32 = 2 ** 31 - 1;
    function validateInt32(value) {
      return Number.isInteger(value) && value <= MAX_INT32 && value >= MIN_INT32;
    }
    function validateInt64(value) {
      return Number.isInteger(value);
    }
    function validateNumber() {
      return true;
    }
    var Z_ANCHOR = /[^\\]\\Z/;
    function regex(str) {
      if (Z_ANCHOR.test(str))
        return false;
      try {
        new RegExp(str);
        return true;
      } catch (e) {
        return false;
      }
    }
  }
});

// node_modules/ajv/dist/runtime/ucs2length.js
var require_ucs2length = __commonJS({
  "node_modules/ajv/dist/runtime/ucs2length.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    function ucs2length(str) {
      const len = str.length;
      let length = 0;
      let pos = 0;
      let value;
      while (pos < len) {
        length++;
        value = str.charCodeAt(pos++);
        if (value >= 55296 && value <= 56319 && pos < len) {
          value = str.charCodeAt(pos);
          if ((value & 64512) === 56320)
            pos++;
        }
      }
      return length;
    }
    exports.default = ucs2length;
    ucs2length.code = 'require("ajv/dist/runtime/ucs2length").default';
  }
});

// node_modules/fast-deep-equal/index.js
var require_fast_deep_equal = __commonJS({
  "node_modules/fast-deep-equal/index.js"(exports, module) {
    "use strict";
    module.exports = function equal(a, b) {
      if (a === b) return true;
      if (a && b && typeof a == "object" && typeof b == "object") {
        if (a.constructor !== b.constructor) return false;
        var length, i, keys;
        if (Array.isArray(a)) {
          length = a.length;
          if (length != b.length) return false;
          for (i = length; i-- !== 0; )
            if (!equal(a[i], b[i])) return false;
          return true;
        }
        if (a.constructor === RegExp) return a.source === b.source && a.flags === b.flags;
        if (a.valueOf !== Object.prototype.valueOf) return a.valueOf() === b.valueOf();
        if (a.toString !== Object.prototype.toString) return a.toString() === b.toString();
        keys = Object.keys(a);
        length = keys.length;
        if (length !== Object.keys(b).length) return false;
        for (i = length; i-- !== 0; )
          if (!Object.prototype.hasOwnProperty.call(b, keys[i])) return false;
        for (i = length; i-- !== 0; ) {
          var key = keys[i];
          if (!equal(a[key], b[key])) return false;
        }
        return true;
      }
      return a !== a && b !== b;
    };
  }
});

// node_modules/ajv/dist/runtime/equal.js
var require_equal = __commonJS({
  "node_modules/ajv/dist/runtime/equal.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var equal = require_fast_deep_equal();
    equal.code = 'require("ajv/dist/runtime/equal").default';
    exports.default = equal;
  }
});

// paasValidate.js
var Application = validate53;
var formats0 = require_formats().fullFormats["date-time"];
var pattern3 = new RegExp("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z$", "u");
function validate55(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate55.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (errors === 0) {
      if (typeof data === "string") {
        if (!pattern3.test(data)) {
          validate55.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z$" }, message: 'must match pattern "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z$"' }];
          return false;
        } else {
          if (!formats0.validate(data)) {
            validate55.errors = [{ instancePath, schemaPath: "#/format", keyword: "format", params: { format: "date-time" }, message: 'must match format "date-time"' }];
            return false;
          }
        }
      } else {
        validate55.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
        return false;
      }
    }
  }
  validate55.errors = vErrors;
  return errors === 0;
}
validate55.evaluated = { "dynamicProps": false, "dynamicItems": false };
var func1 = require_ucs2length().default;
var pattern4 = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", "u");
function validate57(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate57.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (func1(data) > 128) {
        validate57.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate57.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern4.test(data)) {
            validate57.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"' }];
            return false;
          }
        }
      }
    } else {
      validate57.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate57.errors = vErrors;
  return errors === 0;
}
validate57.evaluated = { "dynamicProps": false, "dynamicItems": false };
var pattern5 = new RegExp("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", "u");
function validate60(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate60.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (func1(data) > 63) {
        validate60.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate60.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern5.test(data)) {
            validate60.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
            return false;
          }
        }
      }
    } else {
      validate60.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate60.errors = vErrors;
  return errors === 0;
}
validate60.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate59(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate59.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      if (Object.keys(data).length > 64) {
        validate59.errors = [{ instancePath, schemaPath: "#/maxProperties", keyword: "maxProperties", params: { limit: 64 }, message: "must NOT have more than 64 properties" }];
        return false;
      } else {
        for (const key0 in data) {
          const _errs1 = errors;
          if (!validate60(key0, { instancePath, parentData: data, parentDataProperty, rootData, dynamicAnchors })) {
            vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
            errors = vErrors.length;
          }
          var valid0 = _errs1 === errors;
          if (!valid0) {
            const err0 = { instancePath, schemaPath: "#/propertyNames", keyword: "propertyNames", params: { propertyName: key0 }, message: "property name must be valid" };
            if (vErrors === null) {
              vErrors = [err0];
            } else {
              vErrors.push(err0);
            }
            errors++;
            validate59.errors = vErrors;
            return false;
            break;
          }
        }
        if (valid0) {
          for (const key1 in data) {
            let data0 = data[key1];
            const _errs3 = errors;
            if (errors === _errs3) {
              if (typeof data0 === "string") {
                if (func1(data0) > 128) {
                  validate59.errors = [{ instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/additionalProperties/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
                  return false;
                }
              } else {
                validate59.errors = [{ instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/additionalProperties/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid1 = _errs3 === errors;
            if (!valid1) {
              break;
            }
          }
        }
      }
    } else {
      validate59.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate59.errors = vErrors;
  return errors === 0;
}
validate59.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var schema27 = { "enum": ["PLATFORM", "TENANT"], "type": "string" };
function validate65(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate65.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate65.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PLATFORM" || data === "TENANT")) {
    validate65.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema27.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate65.errors = vErrors;
  return errors === 0;
}
validate65.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate64(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate64.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind")) {
        validate64.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "kind" || key0 === "tenantId")) {
            validate64.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.kind !== void 0) {
            const _errs2 = errors;
            if (!validate65(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate65.errors : vErrors.concat(validate65.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.tenantId !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.tenantId, { instancePath: instancePath + "/tenantId", parentData: data, parentDataProperty: "tenantId", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate64.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate64.errors = vErrors;
  return errors === 0;
}
validate64.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate54(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate54.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.scope === void 0 && (missing0 = "scope") || data.resourceVersion === void 0 && (missing0 = "resourceVersion") || data.createdAt === void 0 && (missing0 = "createdAt") || data.updatedAt === void 0 && (missing0 = "updatedAt")) {
        validate54.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "createdAt" || key0 === "id" || key0 === "labels" || key0 === "name" || key0 === "resourceVersion" || key0 === "scope" || key0 === "updatedAt")) {
            validate54.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.createdAt !== void 0) {
            const _errs2 = errors;
            if (!validate55(data.createdAt, { instancePath: instancePath + "/createdAt", parentData: data, parentDataProperty: "createdAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.id !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.labels !== void 0) {
                const _errs4 = errors;
                if (!validate59(data.labels, { instancePath: instancePath + "/labels", parentData: data, parentDataProperty: "labels", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate59.errors : vErrors.concat(validate59.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.name !== void 0) {
                  const _errs5 = errors;
                  if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.resourceVersion !== void 0) {
                    let data4 = data.resourceVersion;
                    const _errs6 = errors;
                    if (!(typeof data4 == "number" && (!(data4 % 1) && !isNaN(data4)))) {
                      validate54.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                      return false;
                    }
                    if (errors === _errs6) {
                      if (typeof data4 == "number") {
                        if (data4 > 9007199254740991 || isNaN(data4)) {
                          validate54.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                          return false;
                        } else {
                          if (data4 < 0 || isNaN(data4)) {
                            validate54.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                            return false;
                          }
                        }
                      }
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.scope !== void 0) {
                      const _errs8 = errors;
                      if (!validate64(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate64.errors : vErrors.concat(validate64.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.updatedAt !== void 0) {
                        const _errs9 = errors;
                        if (!validate55(data.updatedAt, { instancePath: instancePath + "/updatedAt", parentData: data, parentDataProperty: "updatedAt", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate54.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate54.errors = vErrors;
  return errors === 0;
}
validate54.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate53(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate53.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata")) {
        validate53.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "kind" || key0 === "metadata")) {
            validate53.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("paas.matrix.xiak.com/v1" !== data.apiVersion) {
              validate53.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "paas.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if ("Application" !== data.kind) {
                validate53.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "Application" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.metadata !== void 0) {
                const _errs4 = errors;
                if (!validate54(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate53.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate53.errors = vErrors;
  return errors === 0;
}
validate53.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ApplicationEndpoint = validate71;
var schema29 = { "enum": ["HTTP", "GRPC", "TCP"], "type": "string" };
function validate73(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate73.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate73.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "HTTP" || data === "GRPC" || data === "TCP")) {
    validate73.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema29.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate73.errors = vErrors;
  return errors === 0;
}
validate73.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema30 = { "enum": ["PRIVATE", "PUBLIC"], "type": "string" };
function validate75(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate75.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate75.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PRIVATE" || data === "PUBLIC")) {
    validate75.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema30.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate75.errors = vErrors;
  return errors === 0;
}
validate75.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate71(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate71.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.name === void 0 && (missing0 = "name") || data.port === void 0 && (missing0 = "port") || data.protocol === void 0 && (missing0 = "protocol") || data.visibility === void 0 && (missing0 = "visibility")) {
        validate71.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "name" || key0 === "port" || key0 === "protocol" || key0 === "visibility")) {
            validate71.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.name !== void 0) {
            const _errs2 = errors;
            if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.port !== void 0) {
              let data1 = data.port;
              const _errs3 = errors;
              if (!(typeof data1 == "number" && (!(data1 % 1) && !isNaN(data1)))) {
                validate71.errors = [{ instancePath: instancePath + "/port", schemaPath: "#/properties/port/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                return false;
              }
              if (errors === _errs3) {
                if (typeof data1 == "number") {
                  if (data1 > 65535 || isNaN(data1)) {
                    validate71.errors = [{ instancePath: instancePath + "/port", schemaPath: "#/properties/port/maximum", keyword: "maximum", params: { comparison: "<=", limit: 65535 }, message: "must be <= 65535" }];
                    return false;
                  } else {
                    if (data1 < 1 || isNaN(data1)) {
                      validate71.errors = [{ instancePath: instancePath + "/port", schemaPath: "#/properties/port/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                      return false;
                    }
                  }
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.protocol !== void 0) {
                const _errs5 = errors;
                if (!validate73(data.protocol, { instancePath: instancePath + "/protocol", parentData: data, parentDataProperty: "protocol", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate73.errors : vErrors.concat(validate73.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.visibility !== void 0) {
                  const _errs6 = errors;
                  if (!validate75(data.visibility, { instancePath: instancePath + "/visibility", parentData: data, parentDataProperty: "visibility", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate75.errors : vErrors.concat(validate75.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs6 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate71.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate71.errors = vErrors;
  return errors === 0;
}
validate71.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ApplicationRevision = validate77;
var pattern6 = new RegExp("^sha256:[0-9a-f]{64}$", "u");
function validate83(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate83.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (!pattern6.test(data)) {
        validate83.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
        return false;
      }
    } else {
      validate83.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate83.errors = vErrors;
  return errors === 0;
}
validate83.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema36 = { "enum": ["OCI_IMAGE", "OCI_ARTIFACT", "RELEASE_BUNDLE"], "type": "string" };
function validate85(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate85.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate85.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "OCI_IMAGE" || data === "OCI_ARTIFACT" || data === "RELEASE_BUNDLE")) {
    validate85.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema36.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate85.errors = vErrors;
  return errors === 0;
}
validate85.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate82(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate82.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind") || data.locator === void 0 && (missing0 = "locator") || data.digest === void 0 && (missing0 = "digest")) {
        validate82.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "digest" || key0 === "kind" || key0 === "locator")) {
            validate82.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.digest !== void 0) {
            const _errs2 = errors;
            if (!validate83(data.digest, { instancePath: instancePath + "/digest", parentData: data, parentDataProperty: "digest", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if (!validate85(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate85.errors : vErrors.concat(validate85.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.locator !== void 0) {
                const _errs4 = errors;
                if (typeof data.locator !== "string") {
                  validate82.errors = [{ instancePath: instancePath + "/locator", schemaPath: "#/properties/locator/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate82.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate82.errors = vErrors;
  return errors === 0;
}
validate82.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var schema38 = { "enum": ["ENV", "FILE"], "type": "string" };
function validate90(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate90.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate90.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "ENV" || data === "FILE")) {
    validate90.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema38.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate90.errors = vErrors;
  return errors === 0;
}
validate90.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema39 = { "enum": ["CONFIGURATION", "SECRET"], "type": "string" };
function validate92(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate92.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate92.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CONFIGURATION" || data === "SECRET")) {
    validate92.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema39.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate92.errors = vErrors;
  return errors === 0;
}
validate92.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate89(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate89.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  const _errs1 = errors;
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.kind === void 0 && (missing0 = "kind")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.kind !== void 0) {
        if ("CONFIGURATION" !== data.kind) {
          const err1 = {};
          if (vErrors === null) {
            vErrors = [err1];
          } else {
            vErrors.push(err1);
          }
          errors++;
        }
      }
    }
  }
  var _valid0 = _errs3 === errors;
  errors = _errs2;
  if (vErrors !== null) {
    if (_errs2) {
      vErrors.length = _errs2;
    } else {
      vErrors = null;
    }
  }
  if (_valid0) {
    const _errs5 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      if (data.injection !== void 0) {
        if ("ENV" !== data.injection) {
          validate89.errors = [{ instancePath: instancePath + "/injection", schemaPath: "#/allOf/0/then/properties/injection/const", keyword: "const", params: { allowedValue: "ENV" }, message: "must be equal to constant" }];
          return false;
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.injection = true;
      props0.kind = true;
    }
  }
  if (!valid1) {
    const err2 = { instancePath, schemaPath: "#/allOf/0/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
    if (vErrors === null) {
      vErrors = [err2];
    } else {
      vErrors.push(err2);
    }
    errors++;
    validate89.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs7 = errors;
    const _errs8 = errors;
    let valid4 = true;
    const _errs9 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing1;
      if (data.kind === void 0 && (missing1 = "kind")) {
        const err3 = {};
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      } else {
        if (data.kind !== void 0) {
          if ("SECRET" !== data.kind) {
            const err4 = {};
            if (vErrors === null) {
              vErrors = [err4];
            } else {
              vErrors.push(err4);
            }
            errors++;
          }
        }
      }
    }
    var _valid1 = _errs9 === errors;
    errors = _errs8;
    if (vErrors !== null) {
      if (_errs8) {
        vErrors.length = _errs8;
      } else {
        vErrors = null;
      }
    }
    if (_valid1) {
      const _errs11 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        if (data.injection !== void 0) {
          if ("FILE" !== data.injection) {
            validate89.errors = [{ instancePath: instancePath + "/injection", schemaPath: "#/allOf/1/then/properties/injection/const", keyword: "const", params: { allowedValue: "FILE" }, message: "must be equal to constant" }];
            return false;
          }
        }
      }
      var _valid1 = _errs11 === errors;
      valid4 = _valid1;
      if (valid4) {
        var props1 = {};
        props1.injection = true;
        props1.kind = true;
      }
    }
    if (!valid4) {
      const err5 = { instancePath, schemaPath: "#/allOf/1/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
      validate89.errors = vErrors;
      return false;
    }
    var valid0 = _errs7 === errors;
    if (valid0) {
      if (props0 !== true && props1 !== void 0) {
        if (props1 === true) {
          props0 = true;
        } else {
          props0 = props0 || {};
          Object.assign(props0, props1);
        }
      }
    }
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.name === void 0 && (missing2 = "name") || data.kind === void 0 && (missing2 = "kind") || data.injection === void 0 && (missing2 = "injection") || data.required === void 0 && (missing2 = "required")) {
        validate89.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
        return false;
      } else {
        const _errs13 = errors;
        for (const key0 in data) {
          if (!(key0 === "injection" || key0 === "kind" || key0 === "name" || key0 === "required")) {
            validate89.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs13 === errors) {
          if (data.injection !== void 0) {
            const _errs14 = errors;
            if (!validate90(data.injection, { instancePath: instancePath + "/injection", parentData: data, parentDataProperty: "injection", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate90.errors : vErrors.concat(validate90.errors);
              errors = vErrors.length;
            }
            var valid7 = _errs14 === errors;
          } else {
            var valid7 = true;
          }
          if (valid7) {
            if (data.kind !== void 0) {
              const _errs15 = errors;
              if (!validate92(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate92.errors : vErrors.concat(validate92.errors);
                errors = vErrors.length;
              }
              var valid7 = _errs15 === errors;
            } else {
              var valid7 = true;
            }
            if (valid7) {
              if (data.name !== void 0) {
                const _errs16 = errors;
                if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                  errors = vErrors.length;
                }
                var valid7 = _errs16 === errors;
              } else {
                var valid7 = true;
              }
              if (valid7) {
                if (data.required !== void 0) {
                  const _errs17 = errors;
                  if (typeof data.required !== "boolean") {
                    validate89.errors = [{ instancePath: instancePath + "/required", schemaPath: "#/properties/required/type", keyword: "type", params: { type: "boolean" }, message: "must be boolean" }];
                    return false;
                  }
                  var valid7 = _errs17 === errors;
                } else {
                  var valid7 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate89.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate89.errors = vErrors;
  return errors === 0;
}
validate89.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate97(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate97.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.cpuMillis === void 0 && (missing0 = "cpuMillis") || data.memoryBytes === void 0 && (missing0 = "memoryBytes")) {
        validate97.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "cpuMillis" || key0 === "memoryBytes")) {
            validate97.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.cpuMillis !== void 0) {
            let data0 = data.cpuMillis;
            const _errs2 = errors;
            if (!(typeof data0 == "number" && (!(data0 % 1) && !isNaN(data0)))) {
              validate97.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
              return false;
            }
            if (errors === _errs2) {
              if (typeof data0 == "number") {
                if (data0 > 9007199254740991 || isNaN(data0)) {
                  validate97.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                  return false;
                } else {
                  if (data0 < 0 || isNaN(data0)) {
                    validate97.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                    return false;
                  }
                }
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.memoryBytes !== void 0) {
              let data1 = data.memoryBytes;
              const _errs4 = errors;
              if (!(typeof data1 == "number" && (!(data1 % 1) && !isNaN(data1)))) {
                validate97.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                return false;
              }
              if (errors === _errs4) {
                if (typeof data1 == "number") {
                  if (data1 > 9007199254740991 || isNaN(data1)) {
                    validate97.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                    return false;
                  } else {
                    if (data1 < 0 || isNaN(data1)) {
                      validate97.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                      return false;
                    }
                  }
                }
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate97.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate97.errors = vErrors;
  return errors === 0;
}
validate97.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate81(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate81.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.name === void 0 && (missing0 = "name") || data.artifact === void 0 && (missing0 = "artifact") || data.resources === void 0 && (missing0 = "resources")) {
        validate81.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "artifact" || key0 === "endpoints" || key0 === "inputs" || key0 === "name" || key0 === "resources")) {
            validate81.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.artifact !== void 0) {
            const _errs2 = errors;
            if (!validate82(data.artifact, { instancePath: instancePath + "/artifact", parentData: data, parentDataProperty: "artifact", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate82.errors : vErrors.concat(validate82.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.endpoints !== void 0) {
              let data1 = data.endpoints;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (Array.isArray(data1)) {
                  var valid1 = true;
                  const len0 = data1.length;
                  for (let i0 = 0; i0 < len0; i0++) {
                    const _errs5 = errors;
                    if (!validate71(data1[i0], { instancePath: instancePath + "/endpoints/" + i0, parentData: data1, parentDataProperty: i0, rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate71.errors : vErrors.concat(validate71.errors);
                      errors = vErrors.length;
                    }
                    var valid1 = _errs5 === errors;
                    if (!valid1) {
                      break;
                    }
                  }
                } else {
                  validate81.errors = [{ instancePath: instancePath + "/endpoints", schemaPath: "#/properties/endpoints/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.inputs !== void 0) {
                let data3 = data.inputs;
                const _errs6 = errors;
                if (errors === _errs6) {
                  if (Array.isArray(data3)) {
                    var valid2 = true;
                    const len1 = data3.length;
                    for (let i1 = 0; i1 < len1; i1++) {
                      const _errs8 = errors;
                      if (!validate89(data3[i1], { instancePath: instancePath + "/inputs/" + i1, parentData: data3, parentDataProperty: i1, rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate89.errors : vErrors.concat(validate89.errors);
                        errors = vErrors.length;
                      }
                      var valid2 = _errs8 === errors;
                      if (!valid2) {
                        break;
                      }
                    }
                  } else {
                    validate81.errors = [{ instancePath: instancePath + "/inputs", schemaPath: "#/properties/inputs/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                    return false;
                  }
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.name !== void 0) {
                  const _errs9 = errors;
                  if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs9 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.resources !== void 0) {
                    const _errs10 = errors;
                    if (!validate97(data.resources, { instancePath: instancePath + "/resources", parentData: data, parentDataProperty: "resources", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate97.errors : vErrors.concat(validate97.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs10 === errors;
                  } else {
                    var valid0 = true;
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate81.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate81.errors = vErrors;
  return errors === 0;
}
validate81.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var func0 = require_equal().default;
function validate79(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate79.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.applicationId === void 0 && (missing0 = "applicationId") || data.revision === void 0 && (missing0 = "revision") || data.contentDigest === void 0 && (missing0 = "contentDigest") || data.components === void 0 && (missing0 = "components")) {
        validate79.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "applicationId" || key0 === "components" || key0 === "contentDigest" || key0 === "revision")) {
            validate79.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.applicationId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.applicationId, { instancePath: instancePath + "/applicationId", parentData: data, parentDataProperty: "applicationId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.components !== void 0) {
              let data1 = data.components;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (Array.isArray(data1)) {
                  if (data1.length < 1) {
                    validate79.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/minItems", keyword: "minItems", params: { limit: 1 }, message: "must NOT have fewer than 1 items" }];
                    return false;
                  } else {
                    var valid1 = true;
                    const len0 = data1.length;
                    for (let i0 = 0; i0 < len0; i0++) {
                      const _errs5 = errors;
                      if (!validate81(data1[i0], { instancePath: instancePath + "/components/" + i0, parentData: data1, parentDataProperty: i0, rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate81.errors : vErrors.concat(validate81.errors);
                        errors = vErrors.length;
                      }
                      var valid1 = _errs5 === errors;
                      if (!valid1) {
                        break;
                      }
                    }
                    if (valid1) {
                      let i1 = data1.length;
                      let j0;
                      if (i1 > 1) {
                        outer0:
                          for (; i1--; ) {
                            for (j0 = i1; j0--; ) {
                              if (func0(data1[i1], data1[j0])) {
                                validate79.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/uniqueItems", keyword: "uniqueItems", params: { i: i1, j: j0 }, message: "must NOT have duplicate items (items ## " + j0 + " and " + i1 + " are identical)" }];
                                return false;
                                break outer0;
                              }
                            }
                          }
                      }
                    }
                  }
                } else {
                  validate79.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.contentDigest !== void 0) {
                const _errs6 = errors;
                if (!validate83(data.contentDigest, { instancePath: instancePath + "/contentDigest", parentData: data, parentDataProperty: "contentDigest", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.revision !== void 0) {
                  const _errs7 = errors;
                  if (typeof data.revision !== "string") {
                    validate79.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
                  var valid0 = _errs7 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate79.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate79.errors = vErrors;
  return errors === 0;
}
validate79.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate77(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate77.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata") || data.spec === void 0 && (missing0 = "spec")) {
        validate77.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "kind" || key0 === "metadata" || key0 === "spec")) {
            validate77.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("paas.matrix.xiak.com/v1" !== data.apiVersion) {
              validate77.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "paas.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if ("ApplicationRevision" !== data.kind) {
                validate77.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "ApplicationRevision" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.metadata !== void 0) {
                const _errs4 = errors;
                if (!validate54(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.spec !== void 0) {
                  const _errs5 = errors;
                  if (!validate79(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate79.errors : vErrors.concat(validate79.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate77.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate77.errors = vErrors;
  return errors === 0;
}
validate77.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ApplicationRevisionComponent = validate102;
function validate102(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate102.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.name === void 0 && (missing0 = "name") || data.artifact === void 0 && (missing0 = "artifact") || data.resources === void 0 && (missing0 = "resources")) {
        validate102.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "artifact" || key0 === "endpoints" || key0 === "inputs" || key0 === "name" || key0 === "resources")) {
            validate102.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.artifact !== void 0) {
            const _errs2 = errors;
            if (!validate82(data.artifact, { instancePath: instancePath + "/artifact", parentData: data, parentDataProperty: "artifact", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate82.errors : vErrors.concat(validate82.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.endpoints !== void 0) {
              let data1 = data.endpoints;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (Array.isArray(data1)) {
                  var valid1 = true;
                  const len0 = data1.length;
                  for (let i0 = 0; i0 < len0; i0++) {
                    const _errs5 = errors;
                    if (!validate71(data1[i0], { instancePath: instancePath + "/endpoints/" + i0, parentData: data1, parentDataProperty: i0, rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate71.errors : vErrors.concat(validate71.errors);
                      errors = vErrors.length;
                    }
                    var valid1 = _errs5 === errors;
                    if (!valid1) {
                      break;
                    }
                  }
                } else {
                  validate102.errors = [{ instancePath: instancePath + "/endpoints", schemaPath: "#/properties/endpoints/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.inputs !== void 0) {
                let data3 = data.inputs;
                const _errs6 = errors;
                if (errors === _errs6) {
                  if (Array.isArray(data3)) {
                    var valid2 = true;
                    const len1 = data3.length;
                    for (let i1 = 0; i1 < len1; i1++) {
                      const _errs8 = errors;
                      if (!validate89(data3[i1], { instancePath: instancePath + "/inputs/" + i1, parentData: data3, parentDataProperty: i1, rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate89.errors : vErrors.concat(validate89.errors);
                        errors = vErrors.length;
                      }
                      var valid2 = _errs8 === errors;
                      if (!valid2) {
                        break;
                      }
                    }
                  } else {
                    validate102.errors = [{ instancePath: instancePath + "/inputs", schemaPath: "#/properties/inputs/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                    return false;
                  }
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.name !== void 0) {
                  const _errs9 = errors;
                  if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs9 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.resources !== void 0) {
                    const _errs10 = errors;
                    if (!validate97(data.resources, { instancePath: instancePath + "/resources", parentData: data, parentDataProperty: "resources", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate97.errors : vErrors.concat(validate97.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs10 === errors;
                  } else {
                    var valid0 = true;
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate102.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate102.errors = vErrors;
  return errors === 0;
}
validate102.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ApplicationRevisionSpec = validate108;
function validate108(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate108.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.applicationId === void 0 && (missing0 = "applicationId") || data.revision === void 0 && (missing0 = "revision") || data.contentDigest === void 0 && (missing0 = "contentDigest") || data.components === void 0 && (missing0 = "components")) {
        validate108.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "applicationId" || key0 === "components" || key0 === "contentDigest" || key0 === "revision")) {
            validate108.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.applicationId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.applicationId, { instancePath: instancePath + "/applicationId", parentData: data, parentDataProperty: "applicationId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.components !== void 0) {
              let data1 = data.components;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (Array.isArray(data1)) {
                  if (data1.length < 1) {
                    validate108.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/minItems", keyword: "minItems", params: { limit: 1 }, message: "must NOT have fewer than 1 items" }];
                    return false;
                  } else {
                    var valid1 = true;
                    const len0 = data1.length;
                    for (let i0 = 0; i0 < len0; i0++) {
                      const _errs5 = errors;
                      if (!validate81(data1[i0], { instancePath: instancePath + "/components/" + i0, parentData: data1, parentDataProperty: i0, rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate81.errors : vErrors.concat(validate81.errors);
                        errors = vErrors.length;
                      }
                      var valid1 = _errs5 === errors;
                      if (!valid1) {
                        break;
                      }
                    }
                    if (valid1) {
                      let i1 = data1.length;
                      let j0;
                      if (i1 > 1) {
                        outer0:
                          for (; i1--; ) {
                            for (j0 = i1; j0--; ) {
                              if (func0(data1[i1], data1[j0])) {
                                validate108.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/uniqueItems", keyword: "uniqueItems", params: { i: i1, j: j0 }, message: "must NOT have duplicate items (items ## " + j0 + " and " + i1 + " are identical)" }];
                                return false;
                                break outer0;
                              }
                            }
                          }
                      }
                    }
                  }
                } else {
                  validate108.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.contentDigest !== void 0) {
                const _errs6 = errors;
                if (!validate83(data.contentDigest, { instancePath: instancePath + "/contentDigest", parentData: data, parentDataProperty: "contentDigest", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.revision !== void 0) {
                  const _errs7 = errors;
                  if (typeof data.revision !== "string") {
                    validate108.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
                  var valid0 = _errs7 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate108.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate108.errors = vErrors;
  return errors === 0;
}
validate108.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ArtifactKind = validate112;
function validate112(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate112.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate112.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "OCI_IMAGE" || data === "OCI_ARTIFACT" || data === "RELEASE_BUNDLE")) {
    validate112.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema36.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate112.errors = vErrors;
  return errors === 0;
}
validate112.evaluated = { "dynamicProps": false, "dynamicItems": false };
var ArtifactRef = validate113;
function validate113(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate113.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind") || data.locator === void 0 && (missing0 = "locator") || data.digest === void 0 && (missing0 = "digest")) {
        validate113.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "digest" || key0 === "kind" || key0 === "locator")) {
            validate113.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.digest !== void 0) {
            const _errs2 = errors;
            if (!validate83(data.digest, { instancePath: instancePath + "/digest", parentData: data, parentDataProperty: "digest", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if (!validate85(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate85.errors : vErrors.concat(validate85.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.locator !== void 0) {
                const _errs4 = errors;
                if (typeof data.locator !== "string") {
                  validate113.errors = [{ instancePath: instancePath + "/locator", schemaPath: "#/properties/locator/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate113.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate113.errors = vErrors;
  return errors === 0;
}
validate113.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var AuthorityKind = validate116;
function validate116(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate116.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate116.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PLATFORM" || data === "TENANT")) {
    validate116.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema27.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate116.errors = vErrors;
  return errors === 0;
}
validate116.evaluated = { "dynamicProps": false, "dynamicItems": false };
var ComponentBinding = validate117;
function validate120(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate120.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.secretId === void 0 && (missing0 = "secretId") || data.version === void 0 && (missing0 = "version")) {
        validate120.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "secretId" || key0 === "version")) {
            validate120.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.secretId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.secretId, { instancePath: instancePath + "/secretId", parentData: data, parentDataProperty: "secretId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.version !== void 0) {
              const _errs3 = errors;
              if (typeof data.version !== "string") {
                validate120.errors = [{ instancePath: instancePath + "/version", schemaPath: "#/properties/version/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate120.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate120.errors = vErrors;
  return errors === 0;
}
validate120.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate117(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate117.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  const _errs1 = errors;
  let valid0 = false;
  let passing0 = null;
  const _errs2 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.configurationRevisionId === void 0 && (missing0 = "configurationRevisionId")) {
      const err0 = { instancePath, schemaPath: "#/oneOf/0/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" };
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.secretVersion !== void 0) {
        const err1 = { instancePath: instancePath + "/secretVersion", schemaPath: "#/oneOf/0/properties/secretVersion/false schema", keyword: "false schema", params: {}, message: "boolean schema is false" };
        if (vErrors === null) {
          vErrors = [err1];
        } else {
          vErrors.push(err1);
        }
        errors++;
      }
    }
  }
  var _valid0 = _errs2 === errors;
  if (_valid0) {
    valid0 = true;
    passing0 = 0;
    var props0 = {};
    props0.secretVersion = true;
  }
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing1;
    if (data.secretVersion === void 0 && (missing1 = "secretVersion")) {
      const err2 = { instancePath, schemaPath: "#/oneOf/1/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" };
      if (vErrors === null) {
        vErrors = [err2];
      } else {
        vErrors.push(err2);
      }
      errors++;
    } else {
      if (data.configurationRevisionId !== void 0) {
        const err3 = { instancePath: instancePath + "/configurationRevisionId", schemaPath: "#/oneOf/1/properties/configurationRevisionId/false schema", keyword: "false schema", params: {}, message: "boolean schema is false" };
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      }
    }
  }
  var _valid0 = _errs3 === errors;
  if (_valid0 && valid0) {
    valid0 = false;
    passing0 = [passing0, 1];
  } else {
    if (_valid0) {
      valid0 = true;
      passing0 = 1;
      if (props0 !== true) {
        props0 = props0 || {};
        props0.configurationRevisionId = true;
      }
    }
  }
  if (!valid0) {
    const err4 = { instancePath, schemaPath: "#/oneOf", keyword: "oneOf", params: { passingSchemas: passing0 }, message: "must match exactly one schema in oneOf" };
    if (vErrors === null) {
      vErrors = [err4];
    } else {
      vErrors.push(err4);
    }
    errors++;
    validate117.errors = vErrors;
    return false;
  } else {
    errors = _errs1;
    if (vErrors !== null) {
      if (_errs1) {
        vErrors.length = _errs1;
      } else {
        vErrors = null;
      }
    }
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.name === void 0 && (missing2 = "name")) {
        validate117.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
        return false;
      } else {
        const _errs4 = errors;
        for (const key0 in data) {
          if (!(key0 === "configurationRevisionId" || key0 === "name" || key0 === "secretVersion")) {
            validate117.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs4 === errors) {
          if (data.configurationRevisionId !== void 0) {
            const _errs5 = errors;
            if (!validate57(data.configurationRevisionId, { instancePath: instancePath + "/configurationRevisionId", parentData: data, parentDataProperty: "configurationRevisionId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid3 = _errs5 === errors;
          } else {
            var valid3 = true;
          }
          if (valid3) {
            if (data.name !== void 0) {
              const _errs6 = errors;
              if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                errors = vErrors.length;
              }
              var valid3 = _errs6 === errors;
            } else {
              var valid3 = true;
            }
            if (valid3) {
              if (data.secretVersion !== void 0) {
                const _errs7 = errors;
                if (!validate120(data.secretVersion, { instancePath: instancePath + "/secretVersion", parentData: data, parentDataProperty: "secretVersion", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate120.errors : vErrors.concat(validate120.errors);
                  errors = vErrors.length;
                }
                var valid3 = _errs7 === errors;
              } else {
                var valid3 = true;
              }
            }
          }
        }
      }
    } else {
      validate117.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate117.errors = vErrors;
  return errors === 0;
}
validate117.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ComponentInput = validate123;
function validate123(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate123.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  const _errs1 = errors;
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.kind === void 0 && (missing0 = "kind")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.kind !== void 0) {
        if ("CONFIGURATION" !== data.kind) {
          const err1 = {};
          if (vErrors === null) {
            vErrors = [err1];
          } else {
            vErrors.push(err1);
          }
          errors++;
        }
      }
    }
  }
  var _valid0 = _errs3 === errors;
  errors = _errs2;
  if (vErrors !== null) {
    if (_errs2) {
      vErrors.length = _errs2;
    } else {
      vErrors = null;
    }
  }
  if (_valid0) {
    const _errs5 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      if (data.injection !== void 0) {
        if ("ENV" !== data.injection) {
          validate123.errors = [{ instancePath: instancePath + "/injection", schemaPath: "#/allOf/0/then/properties/injection/const", keyword: "const", params: { allowedValue: "ENV" }, message: "must be equal to constant" }];
          return false;
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.injection = true;
      props0.kind = true;
    }
  }
  if (!valid1) {
    const err2 = { instancePath, schemaPath: "#/allOf/0/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
    if (vErrors === null) {
      vErrors = [err2];
    } else {
      vErrors.push(err2);
    }
    errors++;
    validate123.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs7 = errors;
    const _errs8 = errors;
    let valid4 = true;
    const _errs9 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing1;
      if (data.kind === void 0 && (missing1 = "kind")) {
        const err3 = {};
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      } else {
        if (data.kind !== void 0) {
          if ("SECRET" !== data.kind) {
            const err4 = {};
            if (vErrors === null) {
              vErrors = [err4];
            } else {
              vErrors.push(err4);
            }
            errors++;
          }
        }
      }
    }
    var _valid1 = _errs9 === errors;
    errors = _errs8;
    if (vErrors !== null) {
      if (_errs8) {
        vErrors.length = _errs8;
      } else {
        vErrors = null;
      }
    }
    if (_valid1) {
      const _errs11 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        if (data.injection !== void 0) {
          if ("FILE" !== data.injection) {
            validate123.errors = [{ instancePath: instancePath + "/injection", schemaPath: "#/allOf/1/then/properties/injection/const", keyword: "const", params: { allowedValue: "FILE" }, message: "must be equal to constant" }];
            return false;
          }
        }
      }
      var _valid1 = _errs11 === errors;
      valid4 = _valid1;
      if (valid4) {
        var props1 = {};
        props1.injection = true;
        props1.kind = true;
      }
    }
    if (!valid4) {
      const err5 = { instancePath, schemaPath: "#/allOf/1/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
      if (vErrors === null) {
        vErrors = [err5];
      } else {
        vErrors.push(err5);
      }
      errors++;
      validate123.errors = vErrors;
      return false;
    }
    var valid0 = _errs7 === errors;
    if (valid0) {
      if (props0 !== true && props1 !== void 0) {
        if (props1 === true) {
          props0 = true;
        } else {
          props0 = props0 || {};
          Object.assign(props0, props1);
        }
      }
    }
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.name === void 0 && (missing2 = "name") || data.kind === void 0 && (missing2 = "kind") || data.injection === void 0 && (missing2 = "injection") || data.required === void 0 && (missing2 = "required")) {
        validate123.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
        return false;
      } else {
        const _errs13 = errors;
        for (const key0 in data) {
          if (!(key0 === "injection" || key0 === "kind" || key0 === "name" || key0 === "required")) {
            validate123.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs13 === errors) {
          if (data.injection !== void 0) {
            const _errs14 = errors;
            if (!validate90(data.injection, { instancePath: instancePath + "/injection", parentData: data, parentDataProperty: "injection", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate90.errors : vErrors.concat(validate90.errors);
              errors = vErrors.length;
            }
            var valid7 = _errs14 === errors;
          } else {
            var valid7 = true;
          }
          if (valid7) {
            if (data.kind !== void 0) {
              const _errs15 = errors;
              if (!validate92(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate92.errors : vErrors.concat(validate92.errors);
                errors = vErrors.length;
              }
              var valid7 = _errs15 === errors;
            } else {
              var valid7 = true;
            }
            if (valid7) {
              if (data.name !== void 0) {
                const _errs16 = errors;
                if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                  errors = vErrors.length;
                }
                var valid7 = _errs16 === errors;
              } else {
                var valid7 = true;
              }
              if (valid7) {
                if (data.required !== void 0) {
                  const _errs17 = errors;
                  if (typeof data.required !== "boolean") {
                    validate123.errors = [{ instancePath: instancePath + "/required", schemaPath: "#/properties/required/type", keyword: "type", params: { type: "boolean" }, message: "must be boolean" }];
                    return false;
                  }
                  var valid7 = _errs17 === errors;
                } else {
                  var valid7 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate123.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate123.errors = vErrors;
  return errors === 0;
}
validate123.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var Configuration = validate127;
function validate127(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate127.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata") || data.applicationId === void 0 && (missing0 = "applicationId")) {
        validate127.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "applicationId" || key0 === "kind" || key0 === "metadata")) {
            validate127.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("paas.matrix.xiak.com/v1" !== data.apiVersion) {
              validate127.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "paas.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.applicationId !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.applicationId, { instancePath: instancePath + "/applicationId", parentData: data, parentDataProperty: "applicationId", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.kind !== void 0) {
                const _errs4 = errors;
                if ("Configuration" !== data.kind) {
                  validate127.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "Configuration" }, message: "must be equal to constant" }];
                  return false;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.metadata !== void 0) {
                  const _errs5 = errors;
                  if (!validate54(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate127.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate127.errors = vErrors;
  return errors === 0;
}
validate127.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ConfigurationRevision = validate130;
var pattern7 = new RegExp("^[A-Z_][A-Z0-9_]{0,127}$", "u");
function validate132(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate132.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.configurationId === void 0 && (missing0 = "configurationId") || data.values === void 0 && (missing0 = "values") || data.contentDigest === void 0 && (missing0 = "contentDigest")) {
        validate132.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "configurationId" || key0 === "contentDigest" || key0 === "values")) {
            validate132.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.configurationId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.configurationId, { instancePath: instancePath + "/configurationId", parentData: data, parentDataProperty: "configurationId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.contentDigest !== void 0) {
              const _errs3 = errors;
              if (!validate83(data.contentDigest, { instancePath: instancePath + "/contentDigest", parentData: data, parentDataProperty: "contentDigest", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.values !== void 0) {
                let data2 = data.values;
                const _errs4 = errors;
                if (errors === _errs4) {
                  if (data2 && typeof data2 == "object" && !Array.isArray(data2)) {
                    if (Object.keys(data2).length > 256) {
                      validate132.errors = [{ instancePath: instancePath + "/values", schemaPath: "#/properties/values/maxProperties", keyword: "maxProperties", params: { limit: 256 }, message: "must NOT have more than 256 properties" }];
                      return false;
                    } else {
                      for (const key1 in data2) {
                        const _errs6 = errors;
                        if (typeof key1 === "string") {
                          if (!pattern7.test(key1)) {
                            const err0 = { instancePath: instancePath + "/values", schemaPath: "#/properties/values/propertyNames/pattern", keyword: "pattern", params: { pattern: "^[A-Z_][A-Z0-9_]{0,127}$" }, message: 'must match pattern "^[A-Z_][A-Z0-9_]{0,127}$"', propertyName: key1 };
                            if (vErrors === null) {
                              vErrors = [err0];
                            } else {
                              vErrors.push(err0);
                            }
                            errors++;
                          }
                        }
                        var valid1 = _errs6 === errors;
                        if (!valid1) {
                          const err1 = { instancePath: instancePath + "/values", schemaPath: "#/properties/values/propertyNames", keyword: "propertyNames", params: { propertyName: key1 }, message: "property name must be valid" };
                          if (vErrors === null) {
                            vErrors = [err1];
                          } else {
                            vErrors.push(err1);
                          }
                          errors++;
                          validate132.errors = vErrors;
                          return false;
                          break;
                        }
                      }
                      if (valid1) {
                        for (const key2 in data2) {
                          let data3 = data2[key2];
                          const _errs8 = errors;
                          if (errors === _errs8) {
                            if (typeof data3 === "string") {
                              if (func1(data3) > 32768) {
                                validate132.errors = [{ instancePath: instancePath + "/values/" + key2.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/properties/values/additionalProperties/maxLength", keyword: "maxLength", params: { limit: 32768 }, message: "must NOT have more than 32768 characters" }];
                                return false;
                              }
                            } else {
                              validate132.errors = [{ instancePath: instancePath + "/values/" + key2.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/properties/values/additionalProperties/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                              return false;
                            }
                          }
                          var valid2 = _errs8 === errors;
                          if (!valid2) {
                            break;
                          }
                        }
                      }
                    }
                  } else {
                    validate132.errors = [{ instancePath: instancePath + "/values", schemaPath: "#/properties/values/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
                    return false;
                  }
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate132.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate132.errors = vErrors;
  return errors === 0;
}
validate132.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate130(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate130.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata") || data.spec === void 0 && (missing0 = "spec")) {
        validate130.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "kind" || key0 === "metadata" || key0 === "spec")) {
            validate130.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("paas.matrix.xiak.com/v1" !== data.apiVersion) {
              validate130.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "paas.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if ("ConfigurationRevision" !== data.kind) {
                validate130.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "ConfigurationRevision" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.metadata !== void 0) {
                const _errs4 = errors;
                if (!validate54(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.spec !== void 0) {
                  const _errs5 = errors;
                  if (!validate132(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate132.errors : vErrors.concat(validate132.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate130.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate130.errors = vErrors;
  return errors === 0;
}
validate130.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ConfigurationRevisionSpec = validate136;
function validate136(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate136.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.configurationId === void 0 && (missing0 = "configurationId") || data.values === void 0 && (missing0 = "values") || data.contentDigest === void 0 && (missing0 = "contentDigest")) {
        validate136.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "configurationId" || key0 === "contentDigest" || key0 === "values")) {
            validate136.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.configurationId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.configurationId, { instancePath: instancePath + "/configurationId", parentData: data, parentDataProperty: "configurationId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.contentDigest !== void 0) {
              const _errs3 = errors;
              if (!validate83(data.contentDigest, { instancePath: instancePath + "/contentDigest", parentData: data, parentDataProperty: "contentDigest", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.values !== void 0) {
                let data2 = data.values;
                const _errs4 = errors;
                if (errors === _errs4) {
                  if (data2 && typeof data2 == "object" && !Array.isArray(data2)) {
                    if (Object.keys(data2).length > 256) {
                      validate136.errors = [{ instancePath: instancePath + "/values", schemaPath: "#/properties/values/maxProperties", keyword: "maxProperties", params: { limit: 256 }, message: "must NOT have more than 256 properties" }];
                      return false;
                    } else {
                      for (const key1 in data2) {
                        const _errs6 = errors;
                        if (typeof key1 === "string") {
                          if (!pattern7.test(key1)) {
                            const err0 = { instancePath: instancePath + "/values", schemaPath: "#/properties/values/propertyNames/pattern", keyword: "pattern", params: { pattern: "^[A-Z_][A-Z0-9_]{0,127}$" }, message: 'must match pattern "^[A-Z_][A-Z0-9_]{0,127}$"', propertyName: key1 };
                            if (vErrors === null) {
                              vErrors = [err0];
                            } else {
                              vErrors.push(err0);
                            }
                            errors++;
                          }
                        }
                        var valid1 = _errs6 === errors;
                        if (!valid1) {
                          const err1 = { instancePath: instancePath + "/values", schemaPath: "#/properties/values/propertyNames", keyword: "propertyNames", params: { propertyName: key1 }, message: "property name must be valid" };
                          if (vErrors === null) {
                            vErrors = [err1];
                          } else {
                            vErrors.push(err1);
                          }
                          errors++;
                          validate136.errors = vErrors;
                          return false;
                          break;
                        }
                      }
                      if (valid1) {
                        for (const key2 in data2) {
                          let data3 = data2[key2];
                          const _errs8 = errors;
                          if (errors === _errs8) {
                            if (typeof data3 === "string") {
                              if (func1(data3) > 32768) {
                                validate136.errors = [{ instancePath: instancePath + "/values/" + key2.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/properties/values/additionalProperties/maxLength", keyword: "maxLength", params: { limit: 32768 }, message: "must NOT have more than 32768 characters" }];
                                return false;
                              }
                            } else {
                              validate136.errors = [{ instancePath: instancePath + "/values/" + key2.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/properties/values/additionalProperties/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                              return false;
                            }
                          }
                          var valid2 = _errs8 === errors;
                          if (!valid2) {
                            break;
                          }
                        }
                      }
                    }
                  } else {
                    validate136.errors = [{ instancePath: instancePath + "/values", schemaPath: "#/properties/values/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
                    return false;
                  }
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate136.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate136.errors = vErrors;
  return errors === 0;
}
validate136.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateApplicationRequest = validate139;
function validate139(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate139.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name")) {
        validate139.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "labels" || key0 === "name")) {
            validate139.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.labels !== void 0) {
              const _errs3 = errors;
              if (!validate59(data.labels, { instancePath: instancePath + "/labels", parentData: data, parentDataProperty: "labels", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate59.errors : vErrors.concat(validate59.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.name !== void 0) {
                const _errs4 = errors;
                if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate139.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate139.errors = vErrors;
  return errors === 0;
}
validate139.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateApplicationRevisionRequest = validate143;
function validate143(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate143.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.spec === void 0 && (missing0 = "spec")) {
        validate143.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "labels" || key0 === "name" || key0 === "spec")) {
            validate143.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.labels !== void 0) {
              const _errs3 = errors;
              if (!validate59(data.labels, { instancePath: instancePath + "/labels", parentData: data, parentDataProperty: "labels", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate59.errors : vErrors.concat(validate59.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.name !== void 0) {
                const _errs4 = errors;
                if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.spec !== void 0) {
                  const _errs5 = errors;
                  if (!validate79(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate79.errors : vErrors.concat(validate79.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate143.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate143.errors = vErrors;
  return errors === 0;
}
validate143.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateConfigurationRequest = validate148;
function validate148(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate148.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.applicationId === void 0 && (missing0 = "applicationId")) {
        validate148.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "applicationId" || key0 === "id" || key0 === "labels" || key0 === "name")) {
            validate148.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.applicationId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.applicationId, { instancePath: instancePath + "/applicationId", parentData: data, parentDataProperty: "applicationId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.id !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.labels !== void 0) {
                const _errs4 = errors;
                if (!validate59(data.labels, { instancePath: instancePath + "/labels", parentData: data, parentDataProperty: "labels", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate59.errors : vErrors.concat(validate59.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.name !== void 0) {
                  const _errs5 = errors;
                  if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate148.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate148.errors = vErrors;
  return errors === 0;
}
validate148.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateConfigurationRevisionRequest = validate153;
function validate153(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate153.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.spec === void 0 && (missing0 = "spec")) {
        validate153.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "labels" || key0 === "name" || key0 === "spec")) {
            validate153.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.labels !== void 0) {
              const _errs3 = errors;
              if (!validate59(data.labels, { instancePath: instancePath + "/labels", parentData: data, parentDataProperty: "labels", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate59.errors : vErrors.concat(validate59.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.name !== void 0) {
                const _errs4 = errors;
                if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.spec !== void 0) {
                  const _errs5 = errors;
                  if (!validate132(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate132.errors : vErrors.concat(validate132.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate153.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate153.errors = vErrors;
  return errors === 0;
}
validate153.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateDeploymentRequest = validate158;
function validate163(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate163.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.name === void 0 && (missing0 = "name") || data.replicas === void 0 && (missing0 = "replicas")) {
        validate163.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "bindings" || key0 === "name" || key0 === "replicas")) {
            validate163.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.bindings !== void 0) {
            let data0 = data.bindings;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (Array.isArray(data0)) {
                var valid1 = true;
                const len0 = data0.length;
                for (let i0 = 0; i0 < len0; i0++) {
                  const _errs4 = errors;
                  if (!validate117(data0[i0], { instancePath: instancePath + "/bindings/" + i0, parentData: data0, parentDataProperty: i0, rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate117.errors : vErrors.concat(validate117.errors);
                    errors = vErrors.length;
                  }
                  var valid1 = _errs4 === errors;
                  if (!valid1) {
                    break;
                  }
                }
              } else {
                validate163.errors = [{ instancePath: instancePath + "/bindings", schemaPath: "#/properties/bindings/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.name !== void 0) {
              const _errs5 = errors;
              if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs5 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.replicas !== void 0) {
                let data3 = data.replicas;
                const _errs6 = errors;
                if (!(typeof data3 == "number" && (!(data3 % 1) && !isNaN(data3)))) {
                  validate163.errors = [{ instancePath: instancePath + "/replicas", schemaPath: "#/properties/replicas/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                  return false;
                }
                if (errors === _errs6) {
                  if (typeof data3 == "number") {
                    if (data3 > 4294967295 || isNaN(data3)) {
                      validate163.errors = [{ instancePath: instancePath + "/replicas", schemaPath: "#/properties/replicas/maximum", keyword: "maximum", params: { comparison: "<=", limit: 4294967295 }, message: "must be <= 4294967295" }];
                      return false;
                    } else {
                      if (data3 < 1 || isNaN(data3)) {
                        validate163.errors = [{ instancePath: instancePath + "/replicas", schemaPath: "#/properties/replicas/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                        return false;
                      }
                    }
                  }
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate163.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate163.errors = vErrors;
  return errors === 0;
}
validate163.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var schema60 = { "enum": ["RUNNING", "STOPPED"], "type": "string" };
function validate167(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate167.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate167.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "RUNNING" || data === "STOPPED")) {
    validate167.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema60.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate167.errors = vErrors;
  return errors === 0;
}
validate167.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate161(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate161.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.applicationRevisionId === void 0 && (missing0 = "applicationRevisionId") || data.placementPolicyId === void 0 && (missing0 = "placementPolicyId") || data.desiredState === void 0 && (missing0 = "desiredState") || data.components === void 0 && (missing0 = "components")) {
        validate161.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "applicationRevisionId" || key0 === "components" || key0 === "desiredState" || key0 === "placementPolicyId")) {
            validate161.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.applicationRevisionId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.applicationRevisionId, { instancePath: instancePath + "/applicationRevisionId", parentData: data, parentDataProperty: "applicationRevisionId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.components !== void 0) {
              let data1 = data.components;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (Array.isArray(data1)) {
                  if (data1.length < 1) {
                    validate161.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/minItems", keyword: "minItems", params: { limit: 1 }, message: "must NOT have fewer than 1 items" }];
                    return false;
                  } else {
                    var valid1 = true;
                    const len0 = data1.length;
                    for (let i0 = 0; i0 < len0; i0++) {
                      const _errs5 = errors;
                      if (!validate163(data1[i0], { instancePath: instancePath + "/components/" + i0, parentData: data1, parentDataProperty: i0, rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate163.errors : vErrors.concat(validate163.errors);
                        errors = vErrors.length;
                      }
                      var valid1 = _errs5 === errors;
                      if (!valid1) {
                        break;
                      }
                    }
                    if (valid1) {
                      let i1 = data1.length;
                      let j0;
                      if (i1 > 1) {
                        outer0:
                          for (; i1--; ) {
                            for (j0 = i1; j0--; ) {
                              if (func0(data1[i1], data1[j0])) {
                                validate161.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/uniqueItems", keyword: "uniqueItems", params: { i: i1, j: j0 }, message: "must NOT have duplicate items (items ## " + j0 + " and " + i1 + " are identical)" }];
                                return false;
                                break outer0;
                              }
                            }
                          }
                      }
                    }
                  }
                } else {
                  validate161.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.desiredState !== void 0) {
                const _errs6 = errors;
                if (!validate167(data.desiredState, { instancePath: instancePath + "/desiredState", parentData: data, parentDataProperty: "desiredState", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate167.errors : vErrors.concat(validate167.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.placementPolicyId !== void 0) {
                  const _errs7 = errors;
                  if (!validate57(data.placementPolicyId, { instancePath: instancePath + "/placementPolicyId", parentData: data, parentDataProperty: "placementPolicyId", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs7 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate161.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate161.errors = vErrors;
  return errors === 0;
}
validate161.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate158(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate158.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.spec === void 0 && (missing0 = "spec")) {
        validate158.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "name" || key0 === "spec")) {
            validate158.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.name !== void 0) {
              const _errs3 = errors;
              if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.spec !== void 0) {
                const _errs4 = errors;
                if (!validate161(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate161.errors : vErrors.concat(validate161.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate158.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate158.errors = vErrors;
  return errors === 0;
}
validate158.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var Deployment = validate171;
var schema63 = { "enum": ["PENDING", "PLACING", "APPLYING", "READY", "DEGRADED", "FAILED", "STOPPING", "STOPPED"], "type": "string" };
function validate178(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate178.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate178.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PENDING" || data === "PLACING" || data === "APPLYING" || data === "READY" || data === "DEGRADED" || data === "FAILED" || data === "STOPPING" || data === "STOPPED")) {
    validate178.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema63.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate178.errors = vErrors;
  return errors === 0;
}
validate178.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate174(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate174.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.phase === void 0 && (missing0 = "phase") || data.observedGeneration === void 0 && (missing0 = "observedGeneration") || data.readyComponents === void 0 && (missing0 = "readyComponents") || data.observedAt === void 0 && (missing0 = "observedAt")) {
        validate174.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "currentOperationId" || key0 === "observedApplicationRevisionId" || key0 === "observedAt" || key0 === "observedGeneration" || key0 === "phase" || key0 === "placementDecisionId" || key0 === "readyComponents")) {
            validate174.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.currentOperationId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.currentOperationId, { instancePath: instancePath + "/currentOperationId", parentData: data, parentDataProperty: "currentOperationId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.observedApplicationRevisionId !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.observedApplicationRevisionId, { instancePath: instancePath + "/observedApplicationRevisionId", parentData: data, parentDataProperty: "observedApplicationRevisionId", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.observedAt !== void 0) {
                const _errs4 = errors;
                if (!validate55(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.observedGeneration !== void 0) {
                  let data3 = data.observedGeneration;
                  const _errs5 = errors;
                  if (!(typeof data3 == "number" && (!(data3 % 1) && !isNaN(data3)))) {
                    validate174.errors = [{ instancePath: instancePath + "/observedGeneration", schemaPath: "#/properties/observedGeneration/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                    return false;
                  }
                  if (errors === _errs5) {
                    if (typeof data3 == "number") {
                      if (data3 > 9007199254740991 || isNaN(data3)) {
                        validate174.errors = [{ instancePath: instancePath + "/observedGeneration", schemaPath: "#/properties/observedGeneration/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                        return false;
                      } else {
                        if (data3 < 0 || isNaN(data3)) {
                          validate174.errors = [{ instancePath: instancePath + "/observedGeneration", schemaPath: "#/properties/observedGeneration/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                          return false;
                        }
                      }
                    }
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.phase !== void 0) {
                    const _errs7 = errors;
                    if (!validate178(data.phase, { instancePath: instancePath + "/phase", parentData: data, parentDataProperty: "phase", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate178.errors : vErrors.concat(validate178.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs7 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.placementDecisionId !== void 0) {
                      const _errs8 = errors;
                      if (!validate57(data.placementDecisionId, { instancePath: instancePath + "/placementDecisionId", parentData: data, parentDataProperty: "placementDecisionId", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.readyComponents !== void 0) {
                        let data6 = data.readyComponents;
                        const _errs9 = errors;
                        if (!(typeof data6 == "number" && (!(data6 % 1) && !isNaN(data6)))) {
                          validate174.errors = [{ instancePath: instancePath + "/readyComponents", schemaPath: "#/properties/readyComponents/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                          return false;
                        }
                        if (errors === _errs9) {
                          if (typeof data6 == "number") {
                            if (data6 > 4294967295 || isNaN(data6)) {
                              validate174.errors = [{ instancePath: instancePath + "/readyComponents", schemaPath: "#/properties/readyComponents/maximum", keyword: "maximum", params: { comparison: "<=", limit: 4294967295 }, message: "must be <= 4294967295" }];
                              return false;
                            } else {
                              if (data6 < 0 || isNaN(data6)) {
                                validate174.errors = [{ instancePath: instancePath + "/readyComponents", schemaPath: "#/properties/readyComponents/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                                return false;
                              }
                            }
                          }
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate174.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate174.errors = vErrors;
  return errors === 0;
}
validate174.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate171(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate171.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata") || data.generation === void 0 && (missing0 = "generation") || data.spec === void 0 && (missing0 = "spec") || data.status === void 0 && (missing0 = "status")) {
        validate171.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "generation" || key0 === "kind" || key0 === "metadata" || key0 === "spec" || key0 === "status")) {
            validate171.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("paas.matrix.xiak.com/v1" !== data.apiVersion) {
              validate171.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "paas.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.generation !== void 0) {
              let data1 = data.generation;
              const _errs3 = errors;
              if (!(typeof data1 == "number" && (!(data1 % 1) && !isNaN(data1)))) {
                validate171.errors = [{ instancePath: instancePath + "/generation", schemaPath: "#/properties/generation/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                return false;
              }
              if (errors === _errs3) {
                if (typeof data1 == "number") {
                  if (data1 > 9007199254740991 || isNaN(data1)) {
                    validate171.errors = [{ instancePath: instancePath + "/generation", schemaPath: "#/properties/generation/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                    return false;
                  } else {
                    if (data1 < 1 || isNaN(data1)) {
                      validate171.errors = [{ instancePath: instancePath + "/generation", schemaPath: "#/properties/generation/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                      return false;
                    }
                  }
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.kind !== void 0) {
                const _errs5 = errors;
                if ("Deployment" !== data.kind) {
                  validate171.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "Deployment" }, message: "must be equal to constant" }];
                  return false;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.metadata !== void 0) {
                  const _errs6 = errors;
                  if (!validate54(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs6 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.spec !== void 0) {
                    const _errs7 = errors;
                    if (!validate161(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate161.errors : vErrors.concat(validate161.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs7 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.status !== void 0) {
                      const _errs8 = errors;
                      if (!validate174(data.status, { instancePath: instancePath + "/status", parentData: data, parentDataProperty: "status", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate174.errors : vErrors.concat(validate174.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate171.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate171.errors = vErrors;
  return errors === 0;
}
validate171.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var DeploymentComponent = validate182;
function validate182(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate182.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.name === void 0 && (missing0 = "name") || data.replicas === void 0 && (missing0 = "replicas")) {
        validate182.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "bindings" || key0 === "name" || key0 === "replicas")) {
            validate182.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.bindings !== void 0) {
            let data0 = data.bindings;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (Array.isArray(data0)) {
                var valid1 = true;
                const len0 = data0.length;
                for (let i0 = 0; i0 < len0; i0++) {
                  const _errs4 = errors;
                  if (!validate117(data0[i0], { instancePath: instancePath + "/bindings/" + i0, parentData: data0, parentDataProperty: i0, rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate117.errors : vErrors.concat(validate117.errors);
                    errors = vErrors.length;
                  }
                  var valid1 = _errs4 === errors;
                  if (!valid1) {
                    break;
                  }
                }
              } else {
                validate182.errors = [{ instancePath: instancePath + "/bindings", schemaPath: "#/properties/bindings/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.name !== void 0) {
              const _errs5 = errors;
              if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs5 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.replicas !== void 0) {
                let data3 = data.replicas;
                const _errs6 = errors;
                if (!(typeof data3 == "number" && (!(data3 % 1) && !isNaN(data3)))) {
                  validate182.errors = [{ instancePath: instancePath + "/replicas", schemaPath: "#/properties/replicas/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                  return false;
                }
                if (errors === _errs6) {
                  if (typeof data3 == "number") {
                    if (data3 > 4294967295 || isNaN(data3)) {
                      validate182.errors = [{ instancePath: instancePath + "/replicas", schemaPath: "#/properties/replicas/maximum", keyword: "maximum", params: { comparison: "<=", limit: 4294967295 }, message: "must be <= 4294967295" }];
                      return false;
                    } else {
                      if (data3 < 1 || isNaN(data3)) {
                        validate182.errors = [{ instancePath: instancePath + "/replicas", schemaPath: "#/properties/replicas/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                        return false;
                      }
                    }
                  }
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
            }
          }
        }
      }
    } else {
      validate182.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate182.errors = vErrors;
  return errors === 0;
}
validate182.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var DeploymentDesiredState = validate185;
function validate185(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate185.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate185.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "RUNNING" || data === "STOPPED")) {
    validate185.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema60.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate185.errors = vErrors;
  return errors === 0;
}
validate185.evaluated = { "dynamicProps": false, "dynamicItems": false };
var DeploymentGeneration = validate186;
var schema66 = { "additionalProperties": false, "properties": { "apiVersion": { "const": "paas.matrix.xiak.com/v1" }, "contentDigest": { "$ref": "#/components/schemas/Digest" }, "createdAt": { "$ref": "#/components/schemas/Timestamp" }, "createdByOperationId": { "$ref": "#/components/schemas/ID" }, "deploymentId": { "$ref": "#/components/schemas/ID" }, "generation": { "maximum": 9007199254740991, "minimum": 1, "type": "integer" }, "kind": { "const": "DeploymentGeneration" }, "scope": { "$ref": "#/components/schemas/ResourceScope" }, "spec": { "$ref": "#/components/schemas/DeploymentSpec" } }, "required": ["apiVersion", "kind", "scope", "deploymentId", "generation", "spec", "contentDigest", "createdByOperationId", "createdAt"], "type": "object", "x-matrix-immutable": true };
var func11 = Object.prototype.hasOwnProperty;
function validate186(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate186.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.scope === void 0 && (missing0 = "scope") || data.deploymentId === void 0 && (missing0 = "deploymentId") || data.generation === void 0 && (missing0 = "generation") || data.spec === void 0 && (missing0 = "spec") || data.contentDigest === void 0 && (missing0 = "contentDigest") || data.createdByOperationId === void 0 && (missing0 = "createdByOperationId") || data.createdAt === void 0 && (missing0 = "createdAt")) {
        validate186.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func11.call(schema66.properties, key0)) {
            validate186.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("paas.matrix.xiak.com/v1" !== data.apiVersion) {
              validate186.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "paas.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.contentDigest !== void 0) {
              const _errs3 = errors;
              if (!validate83(data.contentDigest, { instancePath: instancePath + "/contentDigest", parentData: data, parentDataProperty: "contentDigest", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.createdAt !== void 0) {
                const _errs4 = errors;
                if (!validate55(data.createdAt, { instancePath: instancePath + "/createdAt", parentData: data, parentDataProperty: "createdAt", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.createdByOperationId !== void 0) {
                  const _errs5 = errors;
                  if (!validate57(data.createdByOperationId, { instancePath: instancePath + "/createdByOperationId", parentData: data, parentDataProperty: "createdByOperationId", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.deploymentId !== void 0) {
                    const _errs6 = errors;
                    if (!validate57(data.deploymentId, { instancePath: instancePath + "/deploymentId", parentData: data, parentDataProperty: "deploymentId", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.generation !== void 0) {
                      let data5 = data.generation;
                      const _errs7 = errors;
                      if (!(typeof data5 == "number" && (!(data5 % 1) && !isNaN(data5)))) {
                        validate186.errors = [{ instancePath: instancePath + "/generation", schemaPath: "#/properties/generation/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                        return false;
                      }
                      if (errors === _errs7) {
                        if (typeof data5 == "number") {
                          if (data5 > 9007199254740991 || isNaN(data5)) {
                            validate186.errors = [{ instancePath: instancePath + "/generation", schemaPath: "#/properties/generation/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                            return false;
                          } else {
                            if (data5 < 1 || isNaN(data5)) {
                              validate186.errors = [{ instancePath: instancePath + "/generation", schemaPath: "#/properties/generation/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                              return false;
                            }
                          }
                        }
                      }
                      var valid0 = _errs7 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.kind !== void 0) {
                        const _errs9 = errors;
                        if ("DeploymentGeneration" !== data.kind) {
                          validate186.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "DeploymentGeneration" }, message: "must be equal to constant" }];
                          return false;
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.scope !== void 0) {
                          const _errs10 = errors;
                          if (!validate64(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                            vErrors = vErrors === null ? validate64.errors : vErrors.concat(validate64.errors);
                            errors = vErrors.length;
                          }
                          var valid0 = _errs10 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.spec !== void 0) {
                            const _errs11 = errors;
                            if (!validate161(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                              vErrors = vErrors === null ? validate161.errors : vErrors.concat(validate161.errors);
                              errors = vErrors.length;
                            }
                            var valid0 = _errs11 === errors;
                          } else {
                            var valid0 = true;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate186.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate186.errors = vErrors;
  return errors === 0;
}
validate186.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var DeploymentPhase = validate193;
function validate193(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate193.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate193.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PENDING" || data === "PLACING" || data === "APPLYING" || data === "READY" || data === "DEGRADED" || data === "FAILED" || data === "STOPPING" || data === "STOPPED")) {
    validate193.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema63.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate193.errors = vErrors;
  return errors === 0;
}
validate193.evaluated = { "dynamicProps": false, "dynamicItems": false };
var DeploymentSpec = validate194;
function validate194(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate194.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.applicationRevisionId === void 0 && (missing0 = "applicationRevisionId") || data.placementPolicyId === void 0 && (missing0 = "placementPolicyId") || data.desiredState === void 0 && (missing0 = "desiredState") || data.components === void 0 && (missing0 = "components")) {
        validate194.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "applicationRevisionId" || key0 === "components" || key0 === "desiredState" || key0 === "placementPolicyId")) {
            validate194.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.applicationRevisionId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.applicationRevisionId, { instancePath: instancePath + "/applicationRevisionId", parentData: data, parentDataProperty: "applicationRevisionId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.components !== void 0) {
              let data1 = data.components;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (Array.isArray(data1)) {
                  if (data1.length < 1) {
                    validate194.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/minItems", keyword: "minItems", params: { limit: 1 }, message: "must NOT have fewer than 1 items" }];
                    return false;
                  } else {
                    var valid1 = true;
                    const len0 = data1.length;
                    for (let i0 = 0; i0 < len0; i0++) {
                      const _errs5 = errors;
                      if (!validate163(data1[i0], { instancePath: instancePath + "/components/" + i0, parentData: data1, parentDataProperty: i0, rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate163.errors : vErrors.concat(validate163.errors);
                        errors = vErrors.length;
                      }
                      var valid1 = _errs5 === errors;
                      if (!valid1) {
                        break;
                      }
                    }
                    if (valid1) {
                      let i1 = data1.length;
                      let j0;
                      if (i1 > 1) {
                        outer0:
                          for (; i1--; ) {
                            for (j0 = i1; j0--; ) {
                              if (func0(data1[i1], data1[j0])) {
                                validate194.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/uniqueItems", keyword: "uniqueItems", params: { i: i1, j: j0 }, message: "must NOT have duplicate items (items ## " + j0 + " and " + i1 + " are identical)" }];
                                return false;
                                break outer0;
                              }
                            }
                          }
                      }
                    }
                  }
                } else {
                  validate194.errors = [{ instancePath: instancePath + "/components", schemaPath: "#/properties/components/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.desiredState !== void 0) {
                const _errs6 = errors;
                if (!validate167(data.desiredState, { instancePath: instancePath + "/desiredState", parentData: data, parentDataProperty: "desiredState", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate167.errors : vErrors.concat(validate167.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs6 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.placementPolicyId !== void 0) {
                  const _errs7 = errors;
                  if (!validate57(data.placementPolicyId, { instancePath: instancePath + "/placementPolicyId", parentData: data, parentDataProperty: "placementPolicyId", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs7 === errors;
                } else {
                  var valid0 = true;
                }
              }
            }
          }
        }
      }
    } else {
      validate194.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate194.errors = vErrors;
  return errors === 0;
}
validate194.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var DeploymentStatus = validate199;
function validate199(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate199.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.phase === void 0 && (missing0 = "phase") || data.observedGeneration === void 0 && (missing0 = "observedGeneration") || data.readyComponents === void 0 && (missing0 = "readyComponents") || data.observedAt === void 0 && (missing0 = "observedAt")) {
        validate199.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "currentOperationId" || key0 === "observedApplicationRevisionId" || key0 === "observedAt" || key0 === "observedGeneration" || key0 === "phase" || key0 === "placementDecisionId" || key0 === "readyComponents")) {
            validate199.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.currentOperationId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.currentOperationId, { instancePath: instancePath + "/currentOperationId", parentData: data, parentDataProperty: "currentOperationId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.observedApplicationRevisionId !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.observedApplicationRevisionId, { instancePath: instancePath + "/observedApplicationRevisionId", parentData: data, parentDataProperty: "observedApplicationRevisionId", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.observedAt !== void 0) {
                const _errs4 = errors;
                if (!validate55(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.observedGeneration !== void 0) {
                  let data3 = data.observedGeneration;
                  const _errs5 = errors;
                  if (!(typeof data3 == "number" && (!(data3 % 1) && !isNaN(data3)))) {
                    validate199.errors = [{ instancePath: instancePath + "/observedGeneration", schemaPath: "#/properties/observedGeneration/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                    return false;
                  }
                  if (errors === _errs5) {
                    if (typeof data3 == "number") {
                      if (data3 > 9007199254740991 || isNaN(data3)) {
                        validate199.errors = [{ instancePath: instancePath + "/observedGeneration", schemaPath: "#/properties/observedGeneration/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                        return false;
                      } else {
                        if (data3 < 0 || isNaN(data3)) {
                          validate199.errors = [{ instancePath: instancePath + "/observedGeneration", schemaPath: "#/properties/observedGeneration/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                          return false;
                        }
                      }
                    }
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.phase !== void 0) {
                    const _errs7 = errors;
                    if (!validate178(data.phase, { instancePath: instancePath + "/phase", parentData: data, parentDataProperty: "phase", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate178.errors : vErrors.concat(validate178.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs7 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.placementDecisionId !== void 0) {
                      const _errs8 = errors;
                      if (!validate57(data.placementDecisionId, { instancePath: instancePath + "/placementDecisionId", parentData: data, parentDataProperty: "placementDecisionId", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.readyComponents !== void 0) {
                        let data6 = data.readyComponents;
                        const _errs9 = errors;
                        if (!(typeof data6 == "number" && (!(data6 % 1) && !isNaN(data6)))) {
                          validate199.errors = [{ instancePath: instancePath + "/readyComponents", schemaPath: "#/properties/readyComponents/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                          return false;
                        }
                        if (errors === _errs9) {
                          if (typeof data6 == "number") {
                            if (data6 > 4294967295 || isNaN(data6)) {
                              validate199.errors = [{ instancePath: instancePath + "/readyComponents", schemaPath: "#/properties/readyComponents/maximum", keyword: "maximum", params: { comparison: "<=", limit: 4294967295 }, message: "must be <= 4294967295" }];
                              return false;
                            } else {
                              if (data6 < 0 || isNaN(data6)) {
                                validate199.errors = [{ instancePath: instancePath + "/readyComponents", schemaPath: "#/properties/readyComponents/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                                return false;
                              }
                            }
                          }
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate199.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate199.errors = vErrors;
  return errors === 0;
}
validate199.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var Digest = validate205;
function validate205(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate205.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (!pattern6.test(data)) {
        validate205.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
        return false;
      }
    } else {
      validate205.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate205.errors = vErrors;
  return errors === 0;
}
validate205.evaluated = { "dynamicProps": false, "dynamicItems": false };
var EndpointProtocol = validate206;
function validate206(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate206.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate206.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "HTTP" || data === "GRPC" || data === "TCP")) {
    validate206.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema29.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate206.errors = vErrors;
  return errors === 0;
}
validate206.evaluated = { "dynamicProps": false, "dynamicItems": false };
var EndpointVisibility = validate207;
function validate207(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate207.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate207.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PRIVATE" || data === "PUBLIC")) {
    validate207.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema30.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate207.errors = vErrors;
  return errors === 0;
}
validate207.evaluated = { "dynamicProps": false, "dynamicItems": false };
var ErrorCode = validate208;
var schema73 = { "enum": ["INVALID_ARGUMENT", "UNAUTHENTICATED", "PERMISSION_DENIED", "IDENTITY_PROVIDER_UNAVAILABLE", "NOT_FOUND", "ALREADY_EXISTS", "CONFLICT", "RESOURCE_VERSION_CONFLICT", "IDEMPOTENCY_CONFLICT", "UNSCHEDULABLE", "CAPABILITY_UNSUPPORTED", "EXECUTION_TARGET_UNAVAILABLE", "ADAPTER_UNAVAILABLE", "ADAPTER_REJECTED", "ADAPTER_OUTCOME_UNKNOWN", "DEADLINE_EXCEEDED", "OPERATION_FAILED", "MANUAL_INTERVENTION_REQUIRED", "RATE_LIMITED", "INTERNAL"], "type": "string" };
function validate208(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate208.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate208.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "INVALID_ARGUMENT" || data === "UNAUTHENTICATED" || data === "PERMISSION_DENIED" || data === "IDENTITY_PROVIDER_UNAVAILABLE" || data === "NOT_FOUND" || data === "ALREADY_EXISTS" || data === "CONFLICT" || data === "RESOURCE_VERSION_CONFLICT" || data === "IDEMPOTENCY_CONFLICT" || data === "UNSCHEDULABLE" || data === "CAPABILITY_UNSUPPORTED" || data === "EXECUTION_TARGET_UNAVAILABLE" || data === "ADAPTER_UNAVAILABLE" || data === "ADAPTER_REJECTED" || data === "ADAPTER_OUTCOME_UNKNOWN" || data === "DEADLINE_EXCEEDED" || data === "OPERATION_FAILED" || data === "MANUAL_INTERVENTION_REQUIRED" || data === "RATE_LIMITED" || data === "INTERNAL")) {
    validate208.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema73.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate208.errors = vErrors;
  return errors === 0;
}
validate208.evaluated = { "dynamicProps": false, "dynamicItems": false };
var FieldViolation = validate209;
function validate209(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate209.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.field === void 0 && (missing0 = "field") || data.description === void 0 && (missing0 = "description")) {
        validate209.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "description" || key0 === "field")) {
            validate209.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.description !== void 0) {
            const _errs2 = errors;
            if (typeof data.description !== "string") {
              validate209.errors = [{ instancePath: instancePath + "/description", schemaPath: "#/properties/description/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.field !== void 0) {
              const _errs4 = errors;
              if (typeof data.field !== "string") {
                validate209.errors = [{ instancePath: instancePath + "/field", schemaPath: "#/properties/field/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate209.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate209.errors = vErrors;
  return errors === 0;
}
validate209.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ID = validate210;
function validate210(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate210.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (func1(data) > 128) {
        validate210.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate210.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern4.test(data)) {
            validate210.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"' }];
            return false;
          }
        }
      }
    } else {
      validate210.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate210.errors = vErrors;
  return errors === 0;
}
validate210.evaluated = { "dynamicProps": false, "dynamicItems": false };
var InjectionMode = validate211;
function validate211(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate211.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate211.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "ENV" || data === "FILE")) {
    validate211.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema38.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate211.errors = vErrors;
  return errors === 0;
}
validate211.evaluated = { "dynamicProps": false, "dynamicItems": false };
var InputKind = validate212;
function validate212(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate212.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate212.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CONFIGURATION" || data === "SECRET")) {
    validate212.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema39.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate212.errors = vErrors;
  return errors === 0;
}
validate212.evaluated = { "dynamicProps": false, "dynamicItems": false };
var Labels = validate213;
function validate213(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate213.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      if (Object.keys(data).length > 64) {
        validate213.errors = [{ instancePath, schemaPath: "#/maxProperties", keyword: "maxProperties", params: { limit: 64 }, message: "must NOT have more than 64 properties" }];
        return false;
      } else {
        for (const key0 in data) {
          const _errs1 = errors;
          if (!validate60(key0, { instancePath, parentData: data, parentDataProperty, rootData, dynamicAnchors })) {
            vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
            errors = vErrors.length;
          }
          var valid0 = _errs1 === errors;
          if (!valid0) {
            const err0 = { instancePath, schemaPath: "#/propertyNames", keyword: "propertyNames", params: { propertyName: key0 }, message: "property name must be valid" };
            if (vErrors === null) {
              vErrors = [err0];
            } else {
              vErrors.push(err0);
            }
            errors++;
            validate213.errors = vErrors;
            return false;
            break;
          }
        }
        if (valid0) {
          for (const key1 in data) {
            let data0 = data[key1];
            const _errs3 = errors;
            if (errors === _errs3) {
              if (typeof data0 === "string") {
                if (func1(data0) > 128) {
                  validate213.errors = [{ instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/additionalProperties/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
                  return false;
                }
              } else {
                validate213.errors = [{ instancePath: instancePath + "/" + key1.replace(/~/g, "~0").replace(/\//g, "~1"), schemaPath: "#/additionalProperties/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid1 = _errs3 === errors;
            if (!valid1) {
              break;
            }
          }
        }
      }
    } else {
      validate213.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate213.errors = vErrors;
  return errors === 0;
}
validate213.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var Name = validate215;
function validate215(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate215.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (func1(data) > 63) {
        validate215.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate215.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern5.test(data)) {
            validate215.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
            return false;
          }
        }
      }
    } else {
      validate215.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate215.errors = vErrors;
  return errors === 0;
}
validate215.evaluated = { "dynamicProps": false, "dynamicItems": false };
var Operation = validate216;
var schema80 = { "additionalProperties": false, "properties": { "action": { "$ref": "#/components/schemas/OperationAction" }, "apiVersion": { "const": "paas.matrix.xiak.com/v1" }, "attempt": { "maximum": 4294967295, "minimum": 0, "type": "integer" }, "createdAt": { "$ref": "#/components/schemas/Timestamp" }, "error": { "$ref": "#/components/schemas/Problem" }, "id": { "$ref": "#/components/schemas/ID" }, "idempotencyFingerprint": { "$ref": "#/components/schemas/Digest" }, "kind": { "const": "Operation" }, "requestDigest": { "$ref": "#/components/schemas/Digest" }, "requestedBy": { "$ref": "#/components/schemas/SubjectRef" }, "scope": { "$ref": "#/components/schemas/ResourceScope" }, "state": { "$ref": "#/components/schemas/OperationState" }, "target": { "$ref": "#/components/schemas/ResourceRef" }, "terminalAt": { "$ref": "#/components/schemas/Timestamp" }, "updatedAt": { "$ref": "#/components/schemas/Timestamp" } }, "required": ["apiVersion", "kind", "id", "scope", "action", "target", "requestedBy", "idempotencyFingerprint", "requestDigest", "state", "attempt", "createdAt", "updatedAt"], "type": "object" };
var schema81 = { "enum": ["CREATE_EXECUTION_POOL", "REGISTER_EXECUTION_TARGET", "CREATE_PLACEMENT", "CREATE_APPLICATION", "CREATE_CONFIGURATION", "CREATE_CONFIGURATION_REVISION", "CREATE_APPLICATION_REVISION", "DEPLOY", "UPDATE", "STOP", "ROLLBACK"], "type": "string" };
function validate217(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate217.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate217.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CREATE_EXECUTION_POOL" || data === "REGISTER_EXECUTION_TARGET" || data === "CREATE_PLACEMENT" || data === "CREATE_APPLICATION" || data === "CREATE_CONFIGURATION" || data === "CREATE_CONFIGURATION_REVISION" || data === "CREATE_APPLICATION_REVISION" || data === "DEPLOY" || data === "UPDATE" || data === "STOP" || data === "ROLLBACK")) {
    validate217.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema81.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate217.errors = vErrors;
  return errors === 0;
}
validate217.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema82 = { "additionalProperties": false, "properties": { "code": { "$ref": "#/components/schemas/ErrorCode" }, "detail": { "type": "string" }, "instance": { "type": "string" }, "retryable": { "type": "boolean" }, "status": { "maximum": 9007199254740991, "minimum": 0, "type": "integer" }, "title": { "type": "string" }, "traceId": { "$ref": "#/components/schemas/ID" }, "type": { "type": "string" }, "violations": { "items": { "$ref": "#/components/schemas/FieldViolation" }, "type": "array" } }, "required": ["type", "title", "status", "code", "detail", "traceId", "retryable"], "type": "object" };
function validate220(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate220.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.type === void 0 && (missing0 = "type") || data.title === void 0 && (missing0 = "title") || data.status === void 0 && (missing0 = "status") || data.code === void 0 && (missing0 = "code") || data.detail === void 0 && (missing0 = "detail") || data.traceId === void 0 && (missing0 = "traceId") || data.retryable === void 0 && (missing0 = "retryable")) {
        validate220.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func11.call(schema82.properties, key0)) {
            validate220.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.code !== void 0) {
            const _errs2 = errors;
            if (!validate208(data.code, { instancePath: instancePath + "/code", parentData: data, parentDataProperty: "code", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate208.errors : vErrors.concat(validate208.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.detail !== void 0) {
              const _errs3 = errors;
              if (typeof data.detail !== "string") {
                validate220.errors = [{ instancePath: instancePath + "/detail", schemaPath: "#/properties/detail/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.instance !== void 0) {
                const _errs5 = errors;
                if (typeof data.instance !== "string") {
                  validate220.errors = [{ instancePath: instancePath + "/instance", schemaPath: "#/properties/instance/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.retryable !== void 0) {
                  const _errs7 = errors;
                  if (typeof data.retryable !== "boolean") {
                    validate220.errors = [{ instancePath: instancePath + "/retryable", schemaPath: "#/properties/retryable/type", keyword: "type", params: { type: "boolean" }, message: "must be boolean" }];
                    return false;
                  }
                  var valid0 = _errs7 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.status !== void 0) {
                    let data4 = data.status;
                    const _errs9 = errors;
                    if (!(typeof data4 == "number" && (!(data4 % 1) && !isNaN(data4)))) {
                      validate220.errors = [{ instancePath: instancePath + "/status", schemaPath: "#/properties/status/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                      return false;
                    }
                    if (errors === _errs9) {
                      if (typeof data4 == "number") {
                        if (data4 > 9007199254740991 || isNaN(data4)) {
                          validate220.errors = [{ instancePath: instancePath + "/status", schemaPath: "#/properties/status/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                          return false;
                        } else {
                          if (data4 < 0 || isNaN(data4)) {
                            validate220.errors = [{ instancePath: instancePath + "/status", schemaPath: "#/properties/status/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                            return false;
                          }
                        }
                      }
                    }
                    var valid0 = _errs9 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.title !== void 0) {
                      const _errs11 = errors;
                      if (typeof data.title !== "string") {
                        validate220.errors = [{ instancePath: instancePath + "/title", schemaPath: "#/properties/title/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                        return false;
                      }
                      var valid0 = _errs11 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.traceId !== void 0) {
                        const _errs13 = errors;
                        if (!validate57(data.traceId, { instancePath: instancePath + "/traceId", parentData: data, parentDataProperty: "traceId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs13 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.type !== void 0) {
                          const _errs14 = errors;
                          if (typeof data.type !== "string") {
                            validate220.errors = [{ instancePath: instancePath + "/type", schemaPath: "#/properties/type/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                            return false;
                          }
                          var valid0 = _errs14 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.violations !== void 0) {
                            let data8 = data.violations;
                            const _errs16 = errors;
                            if (errors === _errs16) {
                              if (Array.isArray(data8)) {
                                var valid1 = true;
                                const len0 = data8.length;
                                for (let i0 = 0; i0 < len0; i0++) {
                                  const _errs18 = errors;
                                  if (!validate209(data8[i0], { instancePath: instancePath + "/violations/" + i0, parentData: data8, parentDataProperty: i0, rootData, dynamicAnchors })) {
                                    vErrors = vErrors === null ? validate209.errors : vErrors.concat(validate209.errors);
                                    errors = vErrors.length;
                                  }
                                  var valid1 = _errs18 === errors;
                                  if (!valid1) {
                                    break;
                                  }
                                }
                              } else {
                                validate220.errors = [{ instancePath: instancePath + "/violations", schemaPath: "#/properties/violations/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                                return false;
                              }
                            }
                            var valid0 = _errs16 === errors;
                          } else {
                            var valid0 = true;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate220.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate220.errors = vErrors;
  return errors === 0;
}
validate220.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var schema84 = { "enum": ["USER", "SERVICE_ACCOUNT", "AGENT", "SYSTEM_USER"], "type": "string" };
function validate230(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate230.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate230.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "USER" || data === "SERVICE_ACCOUNT" || data === "AGENT" || data === "SYSTEM_USER")) {
    validate230.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema84.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate230.errors = vErrors;
  return errors === 0;
}
validate230.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate228(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate228.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.type === void 0 && (missing0 = "type") || data.id === void 0 && (missing0 = "id")) {
        validate228.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "type")) {
            validate228.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.type !== void 0) {
              const _errs3 = errors;
              if (!validate230(data.type, { instancePath: instancePath + "/type", parentData: data, parentDataProperty: "type", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate230.errors : vErrors.concat(validate230.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate228.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate228.errors = vErrors;
  return errors === 0;
}
validate228.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var schema85 = { "enum": ["ACCEPTED", "PLANNING", "QUEUED", "EXECUTING", "VERIFYING", "RECONCILING", "SUCCEEDED", "FAILED", "CANCELLED", "MANUAL_INTERVENTION"], "type": "string", "x-matrix-terminal-values": ["SUCCEEDED", "FAILED", "CANCELLED", "MANUAL_INTERVENTION"] };
function validate234(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate234.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate234.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "ACCEPTED" || data === "PLANNING" || data === "QUEUED" || data === "EXECUTING" || data === "VERIFYING" || data === "RECONCILING" || data === "SUCCEEDED" || data === "FAILED" || data === "CANCELLED" || data === "MANUAL_INTERVENTION")) {
    validate234.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema85.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate234.errors = vErrors;
  return errors === 0;
}
validate234.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate236(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate236.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind") || data.id === void 0 && (missing0 = "id")) {
        validate236.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "kind")) {
            validate236.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if (typeof data.kind !== "string") {
                validate236.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate236.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate236.errors = vErrors;
  return errors === 0;
}
validate236.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate216(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate216.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.id === void 0 && (missing0 = "id") || data.scope === void 0 && (missing0 = "scope") || data.action === void 0 && (missing0 = "action") || data.target === void 0 && (missing0 = "target") || data.requestedBy === void 0 && (missing0 = "requestedBy") || data.idempotencyFingerprint === void 0 && (missing0 = "idempotencyFingerprint") || data.requestDigest === void 0 && (missing0 = "requestDigest") || data.state === void 0 && (missing0 = "state") || data.attempt === void 0 && (missing0 = "attempt") || data.createdAt === void 0 && (missing0 = "createdAt") || data.updatedAt === void 0 && (missing0 = "updatedAt")) {
        validate216.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func11.call(schema80.properties, key0)) {
            validate216.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.action !== void 0) {
            const _errs2 = errors;
            if (!validate217(data.action, { instancePath: instancePath + "/action", parentData: data, parentDataProperty: "action", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate217.errors : vErrors.concat(validate217.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.apiVersion !== void 0) {
              const _errs3 = errors;
              if ("paas.matrix.xiak.com/v1" !== data.apiVersion) {
                validate216.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "paas.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.attempt !== void 0) {
                let data2 = data.attempt;
                const _errs4 = errors;
                if (!(typeof data2 == "number" && (!(data2 % 1) && !isNaN(data2)))) {
                  validate216.errors = [{ instancePath: instancePath + "/attempt", schemaPath: "#/properties/attempt/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                  return false;
                }
                if (errors === _errs4) {
                  if (typeof data2 == "number") {
                    if (data2 > 4294967295 || isNaN(data2)) {
                      validate216.errors = [{ instancePath: instancePath + "/attempt", schemaPath: "#/properties/attempt/maximum", keyword: "maximum", params: { comparison: "<=", limit: 4294967295 }, message: "must be <= 4294967295" }];
                      return false;
                    } else {
                      if (data2 < 0 || isNaN(data2)) {
                        validate216.errors = [{ instancePath: instancePath + "/attempt", schemaPath: "#/properties/attempt/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                        return false;
                      }
                    }
                  }
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.createdAt !== void 0) {
                  const _errs6 = errors;
                  if (!validate55(data.createdAt, { instancePath: instancePath + "/createdAt", parentData: data, parentDataProperty: "createdAt", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs6 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.error !== void 0) {
                    const _errs7 = errors;
                    if (!validate220(data.error, { instancePath: instancePath + "/error", parentData: data, parentDataProperty: "error", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate220.errors : vErrors.concat(validate220.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs7 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.id !== void 0) {
                      const _errs8 = errors;
                      if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.idempotencyFingerprint !== void 0) {
                        const _errs9 = errors;
                        if (!validate83(data.idempotencyFingerprint, { instancePath: instancePath + "/idempotencyFingerprint", parentData: data, parentDataProperty: "idempotencyFingerprint", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.kind !== void 0) {
                          const _errs10 = errors;
                          if ("Operation" !== data.kind) {
                            validate216.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "Operation" }, message: "must be equal to constant" }];
                            return false;
                          }
                          var valid0 = _errs10 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.requestDigest !== void 0) {
                            const _errs11 = errors;
                            if (!validate83(data.requestDigest, { instancePath: instancePath + "/requestDigest", parentData: data, parentDataProperty: "requestDigest", rootData, dynamicAnchors })) {
                              vErrors = vErrors === null ? validate83.errors : vErrors.concat(validate83.errors);
                              errors = vErrors.length;
                            }
                            var valid0 = _errs11 === errors;
                          } else {
                            var valid0 = true;
                          }
                          if (valid0) {
                            if (data.requestedBy !== void 0) {
                              const _errs12 = errors;
                              if (!validate228(data.requestedBy, { instancePath: instancePath + "/requestedBy", parentData: data, parentDataProperty: "requestedBy", rootData, dynamicAnchors })) {
                                vErrors = vErrors === null ? validate228.errors : vErrors.concat(validate228.errors);
                                errors = vErrors.length;
                              }
                              var valid0 = _errs12 === errors;
                            } else {
                              var valid0 = true;
                            }
                            if (valid0) {
                              if (data.scope !== void 0) {
                                const _errs13 = errors;
                                if (!validate64(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                                  vErrors = vErrors === null ? validate64.errors : vErrors.concat(validate64.errors);
                                  errors = vErrors.length;
                                }
                                var valid0 = _errs13 === errors;
                              } else {
                                var valid0 = true;
                              }
                              if (valid0) {
                                if (data.state !== void 0) {
                                  const _errs14 = errors;
                                  if (!validate234(data.state, { instancePath: instancePath + "/state", parentData: data, parentDataProperty: "state", rootData, dynamicAnchors })) {
                                    vErrors = vErrors === null ? validate234.errors : vErrors.concat(validate234.errors);
                                    errors = vErrors.length;
                                  }
                                  var valid0 = _errs14 === errors;
                                } else {
                                  var valid0 = true;
                                }
                                if (valid0) {
                                  if (data.target !== void 0) {
                                    const _errs15 = errors;
                                    if (!validate236(data.target, { instancePath: instancePath + "/target", parentData: data, parentDataProperty: "target", rootData, dynamicAnchors })) {
                                      vErrors = vErrors === null ? validate236.errors : vErrors.concat(validate236.errors);
                                      errors = vErrors.length;
                                    }
                                    var valid0 = _errs15 === errors;
                                  } else {
                                    var valid0 = true;
                                  }
                                  if (valid0) {
                                    if (data.terminalAt !== void 0) {
                                      const _errs16 = errors;
                                      if (!validate55(data.terminalAt, { instancePath: instancePath + "/terminalAt", parentData: data, parentDataProperty: "terminalAt", rootData, dynamicAnchors })) {
                                        vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                                        errors = vErrors.length;
                                      }
                                      var valid0 = _errs16 === errors;
                                    } else {
                                      var valid0 = true;
                                    }
                                    if (valid0) {
                                      if (data.updatedAt !== void 0) {
                                        const _errs17 = errors;
                                        if (!validate55(data.updatedAt, { instancePath: instancePath + "/updatedAt", parentData: data, parentDataProperty: "updatedAt", rootData, dynamicAnchors })) {
                                          vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                                          errors = vErrors.length;
                                        }
                                        var valid0 = _errs17 === errors;
                                      } else {
                                        var valid0 = true;
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate216.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate216.errors = vErrors;
  return errors === 0;
}
validate216.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var OperationAction = validate241;
function validate241(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate241.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate241.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CREATE_EXECUTION_POOL" || data === "REGISTER_EXECUTION_TARGET" || data === "CREATE_PLACEMENT" || data === "CREATE_APPLICATION" || data === "CREATE_CONFIGURATION" || data === "CREATE_CONFIGURATION_REVISION" || data === "CREATE_APPLICATION_REVISION" || data === "DEPLOY" || data === "UPDATE" || data === "STOP" || data === "ROLLBACK")) {
    validate241.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema81.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate241.errors = vErrors;
  return errors === 0;
}
validate241.evaluated = { "dynamicProps": false, "dynamicItems": false };
var OperationState = validate242;
function validate242(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate242.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate242.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "ACCEPTED" || data === "PLANNING" || data === "QUEUED" || data === "EXECUTING" || data === "VERIFYING" || data === "RECONCILING" || data === "SUCCEEDED" || data === "FAILED" || data === "CANCELLED" || data === "MANUAL_INTERVENTION")) {
    validate242.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema85.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate242.errors = vErrors;
  return errors === 0;
}
validate242.evaluated = { "dynamicProps": false, "dynamicItems": false };
var Problem = validate243;
function validate243(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate243.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.type === void 0 && (missing0 = "type") || data.title === void 0 && (missing0 = "title") || data.status === void 0 && (missing0 = "status") || data.code === void 0 && (missing0 = "code") || data.detail === void 0 && (missing0 = "detail") || data.traceId === void 0 && (missing0 = "traceId") || data.retryable === void 0 && (missing0 = "retryable")) {
        validate243.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func11.call(schema82.properties, key0)) {
            validate243.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.code !== void 0) {
            const _errs2 = errors;
            if (!validate208(data.code, { instancePath: instancePath + "/code", parentData: data, parentDataProperty: "code", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate208.errors : vErrors.concat(validate208.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.detail !== void 0) {
              const _errs3 = errors;
              if (typeof data.detail !== "string") {
                validate243.errors = [{ instancePath: instancePath + "/detail", schemaPath: "#/properties/detail/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.instance !== void 0) {
                const _errs5 = errors;
                if (typeof data.instance !== "string") {
                  validate243.errors = [{ instancePath: instancePath + "/instance", schemaPath: "#/properties/instance/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.retryable !== void 0) {
                  const _errs7 = errors;
                  if (typeof data.retryable !== "boolean") {
                    validate243.errors = [{ instancePath: instancePath + "/retryable", schemaPath: "#/properties/retryable/type", keyword: "type", params: { type: "boolean" }, message: "must be boolean" }];
                    return false;
                  }
                  var valid0 = _errs7 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.status !== void 0) {
                    let data4 = data.status;
                    const _errs9 = errors;
                    if (!(typeof data4 == "number" && (!(data4 % 1) && !isNaN(data4)))) {
                      validate243.errors = [{ instancePath: instancePath + "/status", schemaPath: "#/properties/status/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                      return false;
                    }
                    if (errors === _errs9) {
                      if (typeof data4 == "number") {
                        if (data4 > 9007199254740991 || isNaN(data4)) {
                          validate243.errors = [{ instancePath: instancePath + "/status", schemaPath: "#/properties/status/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                          return false;
                        } else {
                          if (data4 < 0 || isNaN(data4)) {
                            validate243.errors = [{ instancePath: instancePath + "/status", schemaPath: "#/properties/status/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                            return false;
                          }
                        }
                      }
                    }
                    var valid0 = _errs9 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.title !== void 0) {
                      const _errs11 = errors;
                      if (typeof data.title !== "string") {
                        validate243.errors = [{ instancePath: instancePath + "/title", schemaPath: "#/properties/title/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                        return false;
                      }
                      var valid0 = _errs11 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.traceId !== void 0) {
                        const _errs13 = errors;
                        if (!validate57(data.traceId, { instancePath: instancePath + "/traceId", parentData: data, parentDataProperty: "traceId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs13 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.type !== void 0) {
                          const _errs14 = errors;
                          if (typeof data.type !== "string") {
                            validate243.errors = [{ instancePath: instancePath + "/type", schemaPath: "#/properties/type/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                            return false;
                          }
                          var valid0 = _errs14 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.violations !== void 0) {
                            let data8 = data.violations;
                            const _errs16 = errors;
                            if (errors === _errs16) {
                              if (Array.isArray(data8)) {
                                var valid1 = true;
                                const len0 = data8.length;
                                for (let i0 = 0; i0 < len0; i0++) {
                                  const _errs18 = errors;
                                  if (!validate209(data8[i0], { instancePath: instancePath + "/violations/" + i0, parentData: data8, parentDataProperty: i0, rootData, dynamicAnchors })) {
                                    vErrors = vErrors === null ? validate209.errors : vErrors.concat(validate209.errors);
                                    errors = vErrors.length;
                                  }
                                  var valid1 = _errs18 === errors;
                                  if (!valid1) {
                                    break;
                                  }
                                }
                              } else {
                                validate243.errors = [{ instancePath: instancePath + "/violations", schemaPath: "#/properties/violations/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                                return false;
                              }
                            }
                            var valid0 = _errs16 === errors;
                          } else {
                            var valid0 = true;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate243.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate243.errors = vErrors;
  return errors === 0;
}
validate243.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ResourceMetadata = validate247;
function validate247(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate247.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.scope === void 0 && (missing0 = "scope") || data.resourceVersion === void 0 && (missing0 = "resourceVersion") || data.createdAt === void 0 && (missing0 = "createdAt") || data.updatedAt === void 0 && (missing0 = "updatedAt")) {
        validate247.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "createdAt" || key0 === "id" || key0 === "labels" || key0 === "name" || key0 === "resourceVersion" || key0 === "scope" || key0 === "updatedAt")) {
            validate247.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.createdAt !== void 0) {
            const _errs2 = errors;
            if (!validate55(data.createdAt, { instancePath: instancePath + "/createdAt", parentData: data, parentDataProperty: "createdAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.id !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.labels !== void 0) {
                const _errs4 = errors;
                if (!validate59(data.labels, { instancePath: instancePath + "/labels", parentData: data, parentDataProperty: "labels", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate59.errors : vErrors.concat(validate59.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.name !== void 0) {
                  const _errs5 = errors;
                  if (!validate60(data.name, { instancePath: instancePath + "/name", parentData: data, parentDataProperty: "name", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.resourceVersion !== void 0) {
                    let data4 = data.resourceVersion;
                    const _errs6 = errors;
                    if (!(typeof data4 == "number" && (!(data4 % 1) && !isNaN(data4)))) {
                      validate247.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                      return false;
                    }
                    if (errors === _errs6) {
                      if (typeof data4 == "number") {
                        if (data4 > 9007199254740991 || isNaN(data4)) {
                          validate247.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                          return false;
                        } else {
                          if (data4 < 0 || isNaN(data4)) {
                            validate247.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                            return false;
                          }
                        }
                      }
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.scope !== void 0) {
                      const _errs8 = errors;
                      if (!validate64(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate64.errors : vErrors.concat(validate64.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.updatedAt !== void 0) {
                        const _errs9 = errors;
                        if (!validate55(data.updatedAt, { instancePath: instancePath + "/updatedAt", parentData: data, parentDataProperty: "updatedAt", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate55.errors : vErrors.concat(validate55.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate247.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate247.errors = vErrors;
  return errors === 0;
}
validate247.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ResourceRef = validate254;
function validate254(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate254.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind") || data.id === void 0 && (missing0 = "id")) {
        validate254.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "kind")) {
            validate254.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if (typeof data.kind !== "string") {
                validate254.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate254.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate254.errors = vErrors;
  return errors === 0;
}
validate254.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ResourceRequirements = validate256;
function validate256(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate256.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.cpuMillis === void 0 && (missing0 = "cpuMillis") || data.memoryBytes === void 0 && (missing0 = "memoryBytes")) {
        validate256.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "cpuMillis" || key0 === "memoryBytes")) {
            validate256.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.cpuMillis !== void 0) {
            let data0 = data.cpuMillis;
            const _errs2 = errors;
            if (!(typeof data0 == "number" && (!(data0 % 1) && !isNaN(data0)))) {
              validate256.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
              return false;
            }
            if (errors === _errs2) {
              if (typeof data0 == "number") {
                if (data0 > 9007199254740991 || isNaN(data0)) {
                  validate256.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                  return false;
                } else {
                  if (data0 < 0 || isNaN(data0)) {
                    validate256.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                    return false;
                  }
                }
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.memoryBytes !== void 0) {
              let data1 = data.memoryBytes;
              const _errs4 = errors;
              if (!(typeof data1 == "number" && (!(data1 % 1) && !isNaN(data1)))) {
                validate256.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                return false;
              }
              if (errors === _errs4) {
                if (typeof data1 == "number") {
                  if (data1 > 9007199254740991 || isNaN(data1)) {
                    validate256.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                    return false;
                  } else {
                    if (data1 < 0 || isNaN(data1)) {
                      validate256.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                      return false;
                    }
                  }
                }
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate256.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate256.errors = vErrors;
  return errors === 0;
}
validate256.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ResourceScope = validate257;
function validate257(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate257.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind")) {
        validate257.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "kind" || key0 === "tenantId")) {
            validate257.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.kind !== void 0) {
            const _errs2 = errors;
            if (!validate65(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate65.errors : vErrors.concat(validate65.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.tenantId !== void 0) {
              const _errs3 = errors;
              if (!validate57(data.tenantId, { instancePath: instancePath + "/tenantId", parentData: data, parentDataProperty: "tenantId", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate257.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate257.errors = vErrors;
  return errors === 0;
}
validate257.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var RollbackDeploymentRequest = validate260;
function validate260(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate260.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.sourceGeneration === void 0 && (missing0 = "sourceGeneration")) {
        validate260.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "sourceGeneration")) {
            validate260.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.sourceGeneration !== void 0) {
            let data0 = data.sourceGeneration;
            const _errs2 = errors;
            if (!(typeof data0 == "number" && (!(data0 % 1) && !isNaN(data0)))) {
              validate260.errors = [{ instancePath: instancePath + "/sourceGeneration", schemaPath: "#/properties/sourceGeneration/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
              return false;
            }
            if (errors === _errs2) {
              if (typeof data0 == "number") {
                if (data0 > 9007199254740991 || isNaN(data0)) {
                  validate260.errors = [{ instancePath: instancePath + "/sourceGeneration", schemaPath: "#/properties/sourceGeneration/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                  return false;
                } else {
                  if (data0 < 1 || isNaN(data0)) {
                    validate260.errors = [{ instancePath: instancePath + "/sourceGeneration", schemaPath: "#/properties/sourceGeneration/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                    return false;
                  }
                }
              }
            }
          }
        }
      }
    } else {
      validate260.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate260.errors = vErrors;
  return errors === 0;
}
validate260.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var SecretVersionReference = validate261;
function validate261(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate261.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.secretId === void 0 && (missing0 = "secretId") || data.version === void 0 && (missing0 = "version")) {
        validate261.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "secretId" || key0 === "version")) {
            validate261.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.secretId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.secretId, { instancePath: instancePath + "/secretId", parentData: data, parentDataProperty: "secretId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.version !== void 0) {
              const _errs3 = errors;
              if (typeof data.version !== "string") {
                validate261.errors = [{ instancePath: instancePath + "/version", schemaPath: "#/properties/version/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate261.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate261.errors = vErrors;
  return errors === 0;
}
validate261.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var SubjectRef = validate263;
function validate263(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate263.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.type === void 0 && (missing0 = "type") || data.id === void 0 && (missing0 = "id")) {
        validate263.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "type")) {
            validate263.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.type !== void 0) {
              const _errs3 = errors;
              if (!validate230(data.type, { instancePath: instancePath + "/type", parentData: data, parentDataProperty: "type", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate230.errors : vErrors.concat(validate230.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate263.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate263.errors = vErrors;
  return errors === 0;
}
validate263.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var SubjectType = validate266;
function validate266(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate266.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate266.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "USER" || data === "SERVICE_ACCOUNT" || data === "AGENT" || data === "SYSTEM_USER")) {
    validate266.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema84.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate266.errors = vErrors;
  return errors === 0;
}
validate266.evaluated = { "dynamicProps": false, "dynamicItems": false };
var Timestamp = validate267;
function validate267(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate267.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (errors === 0) {
      if (typeof data === "string") {
        if (!pattern3.test(data)) {
          validate267.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z$" }, message: 'must match pattern "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z$"' }];
          return false;
        } else {
          if (!formats0.validate(data)) {
            validate267.errors = [{ instancePath, schemaPath: "#/format", keyword: "format", params: { format: "date-time" }, message: 'must match format "date-time"' }];
            return false;
          }
        }
      } else {
        validate267.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
        return false;
      }
    }
  }
  validate267.errors = vErrors;
  return errors === 0;
}
validate267.evaluated = { "dynamicProps": false, "dynamicItems": false };
export {
  Application,
  ApplicationEndpoint,
  ApplicationRevision,
  ApplicationRevisionComponent,
  ApplicationRevisionSpec,
  ArtifactKind,
  ArtifactRef,
  AuthorityKind,
  ComponentBinding,
  ComponentInput,
  Configuration,
  ConfigurationRevision,
  ConfigurationRevisionSpec,
  CreateApplicationRequest,
  CreateApplicationRevisionRequest,
  CreateConfigurationRequest,
  CreateConfigurationRevisionRequest,
  CreateDeploymentRequest,
  Deployment,
  DeploymentComponent,
  DeploymentDesiredState,
  DeploymentGeneration,
  DeploymentPhase,
  DeploymentSpec,
  DeploymentStatus,
  Digest,
  EndpointProtocol,
  EndpointVisibility,
  ErrorCode,
  FieldViolation,
  ID,
  InjectionMode,
  InputKind,
  Labels,
  Name,
  Operation,
  OperationAction,
  OperationState,
  Problem,
  ResourceMetadata,
  ResourceRef,
  ResourceRequirements,
  ResourceScope,
  RollbackDeploymentRequest,
  SecretVersionReference,
  SubjectRef,
  SubjectType,
  Timestamp
};
