// Generated from api/iam/v1/openapi.json. Run npm run generate:contracts.
var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};

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

// iamValidate.js
var ChangePasswordRequest = validate53;
var func1 = require_ucs2length().default;
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
    if (typeof data === "string") {
      if (func1(data) > 16384) {
        validate54.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 16384 }, message: "must NOT have more than 16384 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate54.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        }
      }
    } else {
      validate54.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate54.errors = vErrors;
  return errors === 0;
}
validate54.evaluated = { "dynamicProps": false, "dynamicItems": false };
var pattern3 = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", "u");
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
          if (!pattern3.test(data)) {
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
      if (data.currentPassword === void 0 && (missing0 = "currentPassword") || data.newPassword === void 0 && (missing0 = "newPassword") || data.requestId === void 0 && (missing0 = "requestId")) {
        validate53.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "currentPassword" || key0 === "newPassword" || key0 === "requestId")) {
            validate53.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.currentPassword !== void 0) {
            const _errs2 = errors;
            if (!validate54(data.currentPassword, { instancePath: instancePath + "/currentPassword", parentData: data, parentDataProperty: "currentPassword", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.newPassword !== void 0) {
              const _errs3 = errors;
              if (!validate54(data.newPassword, { instancePath: instancePath + "/newPassword", parentData: data, parentDataProperty: "newPassword", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.requestId !== void 0) {
                const _errs4 = errors;
                if (!validate57(data.requestId, { instancePath: instancePath + "/requestId", parentData: data, parentDataProperty: "requestId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
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
var ChangePasswordResponse = validate59;
var formats0 = require_formats().fullFormats["date-time"];
var pattern4 = new RegExp("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$", "u");
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
    if (errors === 0) {
      if (typeof data === "string") {
        if (!pattern4.test(data)) {
          validate60.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$" }, message: 'must match pattern "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$"' }];
          return false;
        } else {
          if (!formats0.validate(data)) {
            validate60.errors = [{ instancePath, schemaPath: "#/format", keyword: "format", params: { format: "date-time" }, message: 'must match format "date-time"' }];
            return false;
          }
        }
      } else {
        validate60.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
        return false;
      }
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
      let missing0;
      if (data.bootstrapFileRetirable === void 0 && (missing0 = "bootstrapFileRetirable") || data.changedAt === void 0 && (missing0 = "changedAt")) {
        validate59.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "bootstrapFileRetirable" || key0 === "changedAt")) {
            validate59.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.bootstrapFileRetirable !== void 0) {
            const _errs2 = errors;
            if (typeof data.bootstrapFileRetirable !== "boolean") {
              validate59.errors = [{ instancePath: instancePath + "/bootstrapFileRetirable", schemaPath: "#/properties/bootstrapFileRetirable/type", keyword: "type", params: { type: "boolean" }, message: "must be boolean" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.changedAt !== void 0) {
              const _errs4 = errors;
              if (!validate60(data.changedAt, { instancePath: instancePath + "/changedAt", parentData: data, parentDataProperty: "changedAt", rootData, dynamicAnchors })) {
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
    } else {
      validate59.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate59.errors = vErrors;
  return errors === 0;
}
validate59.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ID = validate62;
function validate62(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate62.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (func1(data) > 128) {
        validate62.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate62.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern3.test(data)) {
            validate62.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"' }];
            return false;
          }
        }
      }
    } else {
      validate62.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate62.errors = vErrors;
  return errors === 0;
}
validate62.evaluated = { "dynamicProps": false, "dynamicItems": false };
var LoginRequest = validate63;
function validate63(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate63.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.loginName === void 0 && (missing0 = "loginName") || data.password === void 0 && (missing0 = "password") || data.requestId === void 0 && (missing0 = "requestId")) {
        validate63.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "loginName" || key0 === "password" || key0 === "requestId")) {
            validate63.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.loginName !== void 0) {
            const _errs2 = errors;
            if (typeof data.loginName !== "string") {
              validate63.errors = [{ instancePath: instancePath + "/loginName", schemaPath: "#/properties/loginName/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.password !== void 0) {
              const _errs4 = errors;
              if (!validate54(data.password, { instancePath: instancePath + "/password", parentData: data, parentDataProperty: "password", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.requestId !== void 0) {
                const _errs5 = errors;
                if (!validate57(data.requestId, { instancePath: instancePath + "/requestId", parentData: data, parentDataProperty: "requestId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
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
    } else {
      validate63.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate63.errors = vErrors;
  return errors === 0;
}
validate63.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var LoginResponse = validate66;
var schema28 = { "additionalProperties": false, "allOf": [{ "else": { "properties": { "revokedAt": false } }, "if": { "properties": { "status": { "const": "REVOKED" } }, "required": ["status"] }, "then": { "required": ["revokedAt"] } }], "properties": { "apiVersion": { "const": "iam.matrix.xiak.com/v1" }, "expiresAt": { "$ref": "#/components/schemas/Timestamp" }, "id": { "$ref": "#/components/schemas/ID" }, "issuedAt": { "$ref": "#/components/schemas/Timestamp" }, "kind": { "const": "Session" }, "organizationId": { "$ref": "#/components/schemas/ID" }, "principalId": { "$ref": "#/components/schemas/ID" }, "revokedAt": { "$ref": "#/components/schemas/Timestamp" }, "status": { "$ref": "#/components/schemas/SessionStatus" } }, "required": ["apiVersion", "expiresAt", "id", "issuedAt", "kind", "organizationId", "principalId", "status"], "type": "object" };
var func7 = Object.prototype.hasOwnProperty;
var schema29 = { "enum": ["ACTIVE", "REVOKED", "EXPIRED"], "type": "string" };
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
  if (!(data === "ACTIVE" || data === "REVOKED" || data === "EXPIRED")) {
    validate75.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema29.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate75.errors = vErrors;
  return errors === 0;
}
validate75.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate68(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate68.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.status === void 0 && (missing0 = "status")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.status !== void 0) {
        if ("REVOKED" !== data.status) {
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
  let ifClause0;
  if (_valid0) {
    const _errs5 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing1;
      if (data.revokedAt === void 0 && (missing1 = "revokedAt")) {
        validate68.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
        return false;
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    ifClause0 = "then";
  } else {
    const _errs6 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      if (data.revokedAt !== void 0) {
        validate68.errors = [{ instancePath: instancePath + "/revokedAt", schemaPath: "#/allOf/0/else/properties/revokedAt/false schema", keyword: "false schema", params: {}, message: "boolean schema is false" }];
        return false;
      }
    }
    var _valid0 = _errs6 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.revokedAt = true;
      props0.status = true;
    }
    ifClause0 = "else";
  }
  if (!valid1) {
    const err2 = { instancePath, schemaPath: "#/allOf/0/if", keyword: "if", params: { failingKeyword: ifClause0 }, message: 'must match "' + ifClause0 + '" schema' };
    if (vErrors === null) {
      vErrors = [err2];
    } else {
      vErrors.push(err2);
    }
    errors++;
    validate68.errors = vErrors;
    return false;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.apiVersion === void 0 && (missing2 = "apiVersion") || data.expiresAt === void 0 && (missing2 = "expiresAt") || data.id === void 0 && (missing2 = "id") || data.issuedAt === void 0 && (missing2 = "issuedAt") || data.kind === void 0 && (missing2 = "kind") || data.organizationId === void 0 && (missing2 = "organizationId") || data.principalId === void 0 && (missing2 = "principalId") || data.status === void 0 && (missing2 = "status")) {
        validate68.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
        return false;
      } else {
        const _errs7 = errors;
        for (const key0 in data) {
          if (!func7.call(schema28.properties, key0)) {
            validate68.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs7 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs8 = errors;
            if ("iam.matrix.xiak.com/v1" !== data.apiVersion) {
              validate68.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "iam.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid4 = _errs8 === errors;
          } else {
            var valid4 = true;
          }
          if (valid4) {
            if (data.expiresAt !== void 0) {
              const _errs9 = errors;
              if (!validate60(data.expiresAt, { instancePath: instancePath + "/expiresAt", parentData: data, parentDataProperty: "expiresAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                errors = vErrors.length;
              }
              var valid4 = _errs9 === errors;
            } else {
              var valid4 = true;
            }
            if (valid4) {
              if (data.id !== void 0) {
                const _errs10 = errors;
                if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid4 = _errs10 === errors;
              } else {
                var valid4 = true;
              }
              if (valid4) {
                if (data.issuedAt !== void 0) {
                  const _errs11 = errors;
                  if (!validate60(data.issuedAt, { instancePath: instancePath + "/issuedAt", parentData: data, parentDataProperty: "issuedAt", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                    errors = vErrors.length;
                  }
                  var valid4 = _errs11 === errors;
                } else {
                  var valid4 = true;
                }
                if (valid4) {
                  if (data.kind !== void 0) {
                    const _errs12 = errors;
                    if ("Session" !== data.kind) {
                      validate68.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "Session" }, message: "must be equal to constant" }];
                      return false;
                    }
                    var valid4 = _errs12 === errors;
                  } else {
                    var valid4 = true;
                  }
                  if (valid4) {
                    if (data.organizationId !== void 0) {
                      const _errs13 = errors;
                      if (!validate57(data.organizationId, { instancePath: instancePath + "/organizationId", parentData: data, parentDataProperty: "organizationId", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                        errors = vErrors.length;
                      }
                      var valid4 = _errs13 === errors;
                    } else {
                      var valid4 = true;
                    }
                    if (valid4) {
                      if (data.principalId !== void 0) {
                        const _errs14 = errors;
                        if (!validate57(data.principalId, { instancePath: instancePath + "/principalId", parentData: data, parentDataProperty: "principalId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                          errors = vErrors.length;
                        }
                        var valid4 = _errs14 === errors;
                      } else {
                        var valid4 = true;
                      }
                      if (valid4) {
                        if (data.revokedAt !== void 0) {
                          const _errs15 = errors;
                          if (!validate60(data.revokedAt, { instancePath: instancePath + "/revokedAt", parentData: data, parentDataProperty: "revokedAt", rootData, dynamicAnchors })) {
                            vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                            errors = vErrors.length;
                          }
                          var valid4 = _errs15 === errors;
                        } else {
                          var valid4 = true;
                        }
                        if (valid4) {
                          if (data.status !== void 0) {
                            const _errs16 = errors;
                            if (!validate75(data.status, { instancePath: instancePath + "/status", parentData: data, parentDataProperty: "status", rootData, dynamicAnchors })) {
                              vErrors = vErrors === null ? validate75.errors : vErrors.concat(validate75.errors);
                              errors = vErrors.length;
                            }
                            var valid4 = _errs16 === errors;
                          } else {
                            var valid4 = true;
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
      validate68.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate68.errors = vErrors;
  return errors === 0;
}
validate68.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate66(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate66.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.credential === void 0 && (missing0 = "credential") || data.session === void 0 && (missing0 = "session")) {
        validate66.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "credential" || key0 === "session")) {
            validate66.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.credential !== void 0) {
            const _errs2 = errors;
            if (!validate54(data.credential, { instancePath: instancePath + "/credential", parentData: data, parentDataProperty: "credential", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.session !== void 0) {
              const _errs3 = errors;
              if (!validate68(data.session, { instancePath: instancePath + "/session", parentData: data, parentDataProperty: "session", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate68.errors : vErrors.concat(validate68.errors);
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
      validate66.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate66.errors = vErrors;
  return errors === 0;
}
validate66.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var LogoutRequest = validate78;
function validate78(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate78.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.requestId === void 0 && (missing0 = "requestId")) {
        validate78.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "requestId")) {
            validate78.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.requestId !== void 0) {
            if (!validate57(data.requestId, { instancePath: instancePath + "/requestId", parentData: data, parentDataProperty: "requestId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
          }
        }
      }
    } else {
      validate78.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate78.errors = vErrors;
  return errors === 0;
}
validate78.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var LogoutResponse = validate80;
function validate80(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate80.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.revokedAt === void 0 && (missing0 = "revokedAt")) {
        validate80.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "revokedAt")) {
            validate80.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.revokedAt !== void 0) {
            if (!validate60(data.revokedAt, { instancePath: instancePath + "/revokedAt", parentData: data, parentDataProperty: "revokedAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
              errors = vErrors.length;
            }
          }
        }
      }
    } else {
      validate80.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate80.errors = vErrors;
  return errors === 0;
}
validate80.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var Secret = validate82;
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
    if (typeof data === "string") {
      if (func1(data) > 16384) {
        validate82.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 16384 }, message: "must NOT have more than 16384 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate82.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        }
      }
    } else {
      validate82.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate82.errors = vErrors;
  return errors === 0;
}
validate82.evaluated = { "dynamicProps": false, "dynamicItems": false };
var Session = validate83;
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
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.status === void 0 && (missing0 = "status")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.status !== void 0) {
        if ("REVOKED" !== data.status) {
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
  let ifClause0;
  if (_valid0) {
    const _errs5 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing1;
      if (data.revokedAt === void 0 && (missing1 = "revokedAt")) {
        validate83.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
        return false;
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    ifClause0 = "then";
  } else {
    const _errs6 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      if (data.revokedAt !== void 0) {
        validate83.errors = [{ instancePath: instancePath + "/revokedAt", schemaPath: "#/allOf/0/else/properties/revokedAt/false schema", keyword: "false schema", params: {}, message: "boolean schema is false" }];
        return false;
      }
    }
    var _valid0 = _errs6 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.revokedAt = true;
      props0.status = true;
    }
    ifClause0 = "else";
  }
  if (!valid1) {
    const err2 = { instancePath, schemaPath: "#/allOf/0/if", keyword: "if", params: { failingKeyword: ifClause0 }, message: 'must match "' + ifClause0 + '" schema' };
    if (vErrors === null) {
      vErrors = [err2];
    } else {
      vErrors.push(err2);
    }
    errors++;
    validate83.errors = vErrors;
    return false;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.apiVersion === void 0 && (missing2 = "apiVersion") || data.expiresAt === void 0 && (missing2 = "expiresAt") || data.id === void 0 && (missing2 = "id") || data.issuedAt === void 0 && (missing2 = "issuedAt") || data.kind === void 0 && (missing2 = "kind") || data.organizationId === void 0 && (missing2 = "organizationId") || data.principalId === void 0 && (missing2 = "principalId") || data.status === void 0 && (missing2 = "status")) {
        validate83.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
        return false;
      } else {
        const _errs7 = errors;
        for (const key0 in data) {
          if (!func7.call(schema28.properties, key0)) {
            validate83.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs7 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs8 = errors;
            if ("iam.matrix.xiak.com/v1" !== data.apiVersion) {
              validate83.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "iam.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid4 = _errs8 === errors;
          } else {
            var valid4 = true;
          }
          if (valid4) {
            if (data.expiresAt !== void 0) {
              const _errs9 = errors;
              if (!validate60(data.expiresAt, { instancePath: instancePath + "/expiresAt", parentData: data, parentDataProperty: "expiresAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                errors = vErrors.length;
              }
              var valid4 = _errs9 === errors;
            } else {
              var valid4 = true;
            }
            if (valid4) {
              if (data.id !== void 0) {
                const _errs10 = errors;
                if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid4 = _errs10 === errors;
              } else {
                var valid4 = true;
              }
              if (valid4) {
                if (data.issuedAt !== void 0) {
                  const _errs11 = errors;
                  if (!validate60(data.issuedAt, { instancePath: instancePath + "/issuedAt", parentData: data, parentDataProperty: "issuedAt", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                    errors = vErrors.length;
                  }
                  var valid4 = _errs11 === errors;
                } else {
                  var valid4 = true;
                }
                if (valid4) {
                  if (data.kind !== void 0) {
                    const _errs12 = errors;
                    if ("Session" !== data.kind) {
                      validate83.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "Session" }, message: "must be equal to constant" }];
                      return false;
                    }
                    var valid4 = _errs12 === errors;
                  } else {
                    var valid4 = true;
                  }
                  if (valid4) {
                    if (data.organizationId !== void 0) {
                      const _errs13 = errors;
                      if (!validate57(data.organizationId, { instancePath: instancePath + "/organizationId", parentData: data, parentDataProperty: "organizationId", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                        errors = vErrors.length;
                      }
                      var valid4 = _errs13 === errors;
                    } else {
                      var valid4 = true;
                    }
                    if (valid4) {
                      if (data.principalId !== void 0) {
                        const _errs14 = errors;
                        if (!validate57(data.principalId, { instancePath: instancePath + "/principalId", parentData: data, parentDataProperty: "principalId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                          errors = vErrors.length;
                        }
                        var valid4 = _errs14 === errors;
                      } else {
                        var valid4 = true;
                      }
                      if (valid4) {
                        if (data.revokedAt !== void 0) {
                          const _errs15 = errors;
                          if (!validate60(data.revokedAt, { instancePath: instancePath + "/revokedAt", parentData: data, parentDataProperty: "revokedAt", rootData, dynamicAnchors })) {
                            vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
                            errors = vErrors.length;
                          }
                          var valid4 = _errs15 === errors;
                        } else {
                          var valid4 = true;
                        }
                        if (valid4) {
                          if (data.status !== void 0) {
                            const _errs16 = errors;
                            if (!validate75(data.status, { instancePath: instancePath + "/status", parentData: data, parentDataProperty: "status", rootData, dynamicAnchors })) {
                              vErrors = vErrors === null ? validate75.errors : vErrors.concat(validate75.errors);
                              errors = vErrors.length;
                            }
                            var valid4 = _errs16 === errors;
                          } else {
                            var valid4 = true;
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
      validate83.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate83.errors = vErrors;
  return errors === 0;
}
validate83.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var SessionStatus = validate91;
function validate91(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate91.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate91.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "ACTIVE" || data === "REVOKED" || data === "EXPIRED")) {
    validate91.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema29.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate91.errors = vErrors;
  return errors === 0;
}
validate91.evaluated = { "dynamicProps": false, "dynamicItems": false };
var Timestamp = validate92;
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
  if (errors === 0) {
    if (errors === 0) {
      if (typeof data === "string") {
        if (!pattern4.test(data)) {
          validate92.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$" }, message: 'must match pattern "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$"' }];
          return false;
        } else {
          if (!formats0.validate(data)) {
            validate92.errors = [{ instancePath, schemaPath: "#/format", keyword: "format", params: { format: "date-time" }, message: 'must match format "date-time"' }];
            return false;
          }
        }
      } else {
        validate92.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
        return false;
      }
    }
  }
  validate92.errors = vErrors;
  return errors === 0;
}
validate92.evaluated = { "dynamicProps": false, "dynamicItems": false };
export {
  ChangePasswordRequest,
  ChangePasswordResponse,
  ID,
  LoginRequest,
  LoginResponse,
  LogoutRequest,
  LogoutResponse,
  Secret,
  Session,
  SessionStatus,
  Timestamp
};
