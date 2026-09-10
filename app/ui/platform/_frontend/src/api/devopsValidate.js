// Generated from api/devops/v1/openapi.json. Run npm run generate:contracts.
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

// devopsValidate.js
var ChangeAction = validate53;
var schema20 = { "enum": ["OPENED", "REOPENED", "UPDATED"], "type": "string" };
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
  if (typeof data !== "string") {
    validate53.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "OPENED" || data === "REOPENED" || data === "UPDATED")) {
    validate53.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema20.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate53.errors = vErrors;
  return errors === 0;
}
validate53.evaluated = { "dynamicProps": false, "dynamicItems": false };
var ChangeIdentity = validate54;
var pattern3 = new RegExp("^(?:[0-9a-f]{40}|[0-9a-f]{64})$", "u");
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
      if (data.action === void 0 && (missing0 = "action") || data.headCommit === void 0 && (missing0 = "headCommit") || data.number === void 0 && (missing0 = "number") || data.trustedBaseCommit === void 0 && (missing0 = "trustedBaseCommit")) {
        validate54.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "action" || key0 === "headCommit" || key0 === "number" || key0 === "trustedBaseCommit")) {
            validate54.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.action !== void 0) {
            const _errs2 = errors;
            if (!validate53(data.action, { instancePath: instancePath + "/action", parentData: data, parentDataProperty: "action", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate53.errors : vErrors.concat(validate53.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.headCommit !== void 0) {
              let data1 = data.headCommit;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (!pattern3.test(data1)) {
                    validate54.errors = [{ instancePath: instancePath + "/headCommit", schemaPath: "#/properties/headCommit/pattern", keyword: "pattern", params: { pattern: "^(?:[0-9a-f]{40}|[0-9a-f]{64})$" }, message: 'must match pattern "^(?:[0-9a-f]{40}|[0-9a-f]{64})$"' }];
                    return false;
                  }
                } else {
                  validate54.errors = [{ instancePath: instancePath + "/headCommit", schemaPath: "#/properties/headCommit/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.number !== void 0) {
                let data2 = data.number;
                const _errs5 = errors;
                if (!(typeof data2 == "number" && (!(data2 % 1) && !isNaN(data2)))) {
                  validate54.errors = [{ instancePath: instancePath + "/number", schemaPath: "#/properties/number/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                  return false;
                }
                if (errors === _errs5) {
                  if (typeof data2 == "number") {
                    if (data2 > 9007199254740991 || isNaN(data2)) {
                      validate54.errors = [{ instancePath: instancePath + "/number", schemaPath: "#/properties/number/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                      return false;
                    } else {
                      if (data2 < 1 || isNaN(data2)) {
                        validate54.errors = [{ instancePath: instancePath + "/number", schemaPath: "#/properties/number/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
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
                if (data.trustedBaseCommit !== void 0) {
                  let data3 = data.trustedBaseCommit;
                  const _errs7 = errors;
                  if (errors === _errs7) {
                    if (typeof data3 === "string") {
                      if (!pattern3.test(data3)) {
                        validate54.errors = [{ instancePath: instancePath + "/trustedBaseCommit", schemaPath: "#/properties/trustedBaseCommit/pattern", keyword: "pattern", params: { pattern: "^(?:[0-9a-f]{40}|[0-9a-f]{64})$" }, message: 'must match pattern "^(?:[0-9a-f]{40}|[0-9a-f]{64})$"' }];
                        return false;
                      }
                    } else {
                      validate54.errors = [{ instancePath: instancePath + "/trustedBaseCommit", schemaPath: "#/properties/trustedBaseCommit/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                      return false;
                    }
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
      validate54.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate54.errors = vErrors;
  return errors === 0;
}
validate54.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateDevOpsProjectRequest = validate56;
var func1 = require_ucs2length().default;
var pattern5 = new RegExp("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", "u");
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
          if (!pattern5.test(data)) {
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
var pattern6 = new RegExp("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", "u");
function validate56(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate56.evaluated;
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
        validate56.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "name")) {
            validate56.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
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
              let data1 = data.name;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (func1(data1) > 63) {
                    validate56.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
                    return false;
                  } else {
                    if (func1(data1) < 1) {
                      validate56.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                      return false;
                    } else {
                      if (!pattern6.test(data1)) {
                        validate56.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
                        return false;
                      }
                    }
                  }
                } else {
                  validate56.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate56.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate56.errors = vErrors;
  return errors === 0;
}
validate56.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreatePipelineRequest = validate59;
var schema26 = { "enum": ["NONE"], "type": "string" };
function validate61(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate61.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate61.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "NONE")) {
    validate61.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema26.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate61.errors = vErrors;
  return errors === 0;
}
validate61.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema27 = { "enum": ["CHANGE_CHECK_V1"], "type": "string" };
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
  if (typeof data !== "string") {
    validate63.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CHANGE_CHECK_V1")) {
    validate63.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema27.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate63.errors = vErrors;
  return errors === 0;
}
validate63.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema28 = { "enum": ["CHANGE"], "type": "string" };
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
  if (typeof data !== "string") {
    validate66.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CHANGE")) {
    validate66.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema28.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate66.errors = vErrors;
  return errors === 0;
}
validate66.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema29 = { "enum": ["GO_1_26_OFFLINE_V1"], "type": "string" };
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
  if (typeof data !== "string") {
    validate68.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "GO_1_26_OFFLINE_V1")) {
    validate68.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema29.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate68.errors = vErrors;
  return errors === 0;
}
validate68.evaluated = { "dynamicProps": false, "dynamicItems": false };
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
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.dependencyEgress === void 0 && (missing0 = "dependencyEgress") || data.reporterPolicy === void 0 && (missing0 = "reporterPolicy") || data.repositoryBindingId === void 0 && (missing0 = "repositoryBindingId") || data.triggerPolicy === void 0 && (missing0 = "triggerPolicy") || data.verificationProfile === void 0 && (missing0 = "verificationProfile")) {
        validate60.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "dependencyEgress" || key0 === "reporterPolicy" || key0 === "repositoryBindingId" || key0 === "triggerPolicy" || key0 === "verificationProfile")) {
            validate60.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.dependencyEgress !== void 0) {
            const _errs2 = errors;
            if (!validate61(data.dependencyEgress, { instancePath: instancePath + "/dependencyEgress", parentData: data, parentDataProperty: "dependencyEgress", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate61.errors : vErrors.concat(validate61.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.reporterPolicy !== void 0) {
              const _errs3 = errors;
              if (!validate63(data.reporterPolicy, { instancePath: instancePath + "/reporterPolicy", parentData: data, parentDataProperty: "reporterPolicy", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate63.errors : vErrors.concat(validate63.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.repositoryBindingId !== void 0) {
                const _errs4 = errors;
                if (!validate57(data.repositoryBindingId, { instancePath: instancePath + "/repositoryBindingId", parentData: data, parentDataProperty: "repositoryBindingId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.triggerPolicy !== void 0) {
                  const _errs5 = errors;
                  if (!validate66(data.triggerPolicy, { instancePath: instancePath + "/triggerPolicy", parentData: data, parentDataProperty: "triggerPolicy", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate66.errors : vErrors.concat(validate66.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.verificationProfile !== void 0) {
                    const _errs6 = errors;
                    if (!validate68(data.verificationProfile, { instancePath: instancePath + "/verificationProfile", parentData: data, parentDataProperty: "verificationProfile", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate68.errors : vErrors.concat(validate68.errors);
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
      }
    } else {
      validate60.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate60.errors = vErrors;
  return errors === 0;
}
validate60.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
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
      if (data.draft === void 0 && (missing0 = "draft") || data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.projectId === void 0 && (missing0 = "projectId")) {
        validate59.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "draft" || key0 === "id" || key0 === "name" || key0 === "projectId")) {
            validate59.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.draft !== void 0) {
            const _errs2 = errors;
            if (!validate60(data.draft, { instancePath: instancePath + "/draft", parentData: data, parentDataProperty: "draft", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
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
              if (data.name !== void 0) {
                let data2 = data.name;
                const _errs4 = errors;
                if (errors === _errs4) {
                  if (typeof data2 === "string") {
                    if (func1(data2) > 63) {
                      validate59.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
                      return false;
                    } else {
                      if (func1(data2) < 1) {
                        validate59.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                        return false;
                      } else {
                        if (!pattern6.test(data2)) {
                          validate59.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
                          return false;
                        }
                      }
                    }
                  } else {
                    validate59.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.projectId !== void 0) {
                  const _errs6 = errors;
                  if (!validate57(data.projectId, { instancePath: instancePath + "/projectId", parentData: data, parentDataProperty: "projectId", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
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
      validate59.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate59.errors = vErrors;
  return errors === 0;
}
validate59.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateRepositoryBindingRequest = validate73;
var pattern9 = new RegExp("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", "u");
var pattern10 = new RegExp("(?:\\.\\.|//|@\\{|(?:^|/)\\.|\\.lock(?:/|$)|[/.]$)", "u");
var pattern11 = new RegExp("^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$", "u");
function validate76(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate76.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.externalRepositoryId === void 0 && (missing0 = "externalRepositoryId") || data.repositoryPath === void 0 && (missing0 = "repositoryPath") || data.sourceConnectionId === void 0 && (missing0 = "sourceConnectionId") || data.trustedDefaultBranch === void 0 && (missing0 = "trustedDefaultBranch")) {
        validate76.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "externalRepositoryId" || key0 === "repositoryPath" || key0 === "sourceConnectionId" || key0 === "trustedDefaultBranch")) {
            validate76.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.externalRepositoryId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.externalRepositoryId, { instancePath: instancePath + "/externalRepositoryId", parentData: data, parentDataProperty: "externalRepositoryId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.repositoryPath !== void 0) {
              let data1 = data.repositoryPath;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (func1(data1) > 257) {
                    validate76.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/maxLength", keyword: "maxLength", params: { limit: 257 }, message: "must NOT have more than 257 characters" }];
                    return false;
                  } else {
                    if (func1(data1) < 3) {
                      validate76.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/minLength", keyword: "minLength", params: { limit: 3 }, message: "must NOT have fewer than 3 characters" }];
                      return false;
                    } else {
                      if (!pattern9.test(data1)) {
                        validate76.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"' }];
                        return false;
                      }
                    }
                  }
                } else {
                  validate76.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.sourceConnectionId !== void 0) {
                const _errs5 = errors;
                if (!validate57(data.sourceConnectionId, { instancePath: instancePath + "/sourceConnectionId", parentData: data, parentDataProperty: "sourceConnectionId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.trustedDefaultBranch !== void 0) {
                  let data3 = data.trustedDefaultBranch;
                  const _errs6 = errors;
                  const _errs8 = errors;
                  const _errs9 = errors;
                  if (typeof data3 === "string") {
                    if (!pattern10.test(data3)) {
                      const err0 = {};
                      if (vErrors === null) {
                        vErrors = [err0];
                      } else {
                        vErrors.push(err0);
                      }
                      errors++;
                    }
                  }
                  var valid1 = _errs9 === errors;
                  if (valid1) {
                    validate76.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/not", keyword: "not", params: {}, message: "must NOT be valid" }];
                    return false;
                  } else {
                    errors = _errs8;
                    if (vErrors !== null) {
                      if (_errs8) {
                        vErrors.length = _errs8;
                      } else {
                        vErrors = null;
                      }
                    }
                  }
                  if (errors === _errs6) {
                    if (typeof data3 === "string") {
                      if (func1(data3) > 128) {
                        validate76.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
                        return false;
                      } else {
                        if (func1(data3) < 1) {
                          validate76.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                          return false;
                        } else {
                          if (!pattern11.test(data3)) {
                            validate76.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$"' }];
                            return false;
                          }
                        }
                      }
                    } else {
                      validate76.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                      return false;
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
      }
    } else {
      validate76.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate76.errors = vErrors;
  return errors === 0;
}
validate76.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.projectId === void 0 && (missing0 = "projectId") || data.spec === void 0 && (missing0 = "spec")) {
        validate73.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "name" || key0 === "projectId" || key0 === "spec")) {
            validate73.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
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
              let data1 = data.name;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (func1(data1) > 63) {
                    validate73.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
                    return false;
                  } else {
                    if (func1(data1) < 1) {
                      validate73.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                      return false;
                    } else {
                      if (!pattern6.test(data1)) {
                        validate73.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
                        return false;
                      }
                    }
                  }
                } else {
                  validate73.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.projectId !== void 0) {
                const _errs5 = errors;
                if (!validate57(data.projectId, { instancePath: instancePath + "/projectId", parentData: data, parentDataProperty: "projectId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.spec !== void 0) {
                  const _errs6 = errors;
                  if (!validate76(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate76.errors : vErrors.concat(validate76.errors);
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
      validate73.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate73.errors = vErrors;
  return errors === 0;
}
validate73.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var CreateSourceConnectionRequest = validate80;
var pattern13 = new RegExp("^https://(?:[a-z0-9-]+\\.)*localhost(?::|$)", "u");
var pattern14 = new RegExp("^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$", "u");
var formats0 = require_formats().fullFormats.uri;
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
      if (data.adapterId === void 0 && (missing0 = "adapterId") || data.endpointOrigin === void 0 && (missing0 = "endpointOrigin") || data.fetchCredentialRef === void 0 && (missing0 = "fetchCredentialRef") || data.reportCredentialRef === void 0 && (missing0 = "reportCredentialRef") || data.webhookSecretRef === void 0 && (missing0 = "webhookSecretRef")) {
        validate82.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "adapterId" || key0 === "endpointOrigin" || key0 === "fetchCredentialRef" || key0 === "reportCredentialRef" || key0 === "webhookSecretRef")) {
            validate82.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.adapterId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.adapterId, { instancePath: instancePath + "/adapterId", parentData: data, parentDataProperty: "adapterId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.endpointOrigin !== void 0) {
              let data1 = data.endpointOrigin;
              const _errs3 = errors;
              const _errs5 = errors;
              const _errs6 = errors;
              if (typeof data1 === "string") {
                if (!pattern13.test(data1)) {
                  const err0 = {};
                  if (vErrors === null) {
                    vErrors = [err0];
                  } else {
                    vErrors.push(err0);
                  }
                  errors++;
                }
              }
              var valid1 = _errs6 === errors;
              if (valid1) {
                validate82.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/not", keyword: "not", params: {}, message: "must NOT be valid" }];
                return false;
              } else {
                errors = _errs5;
                if (vErrors !== null) {
                  if (_errs5) {
                    vErrors.length = _errs5;
                  } else {
                    vErrors = null;
                  }
                }
              }
              if (errors === _errs3) {
                if (errors === _errs3) {
                  if (typeof data1 === "string") {
                    if (func1(data1) > 512) {
                      validate82.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/maxLength", keyword: "maxLength", params: { limit: 512 }, message: "must NOT have more than 512 characters" }];
                      return false;
                    } else {
                      if (func1(data1) < 1) {
                        validate82.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                        return false;
                      } else {
                        if (!pattern14.test(data1)) {
                          validate82.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/pattern", keyword: "pattern", params: { pattern: "^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$" }, message: 'must match pattern "^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$"' }];
                          return false;
                        } else {
                          if (!formats0(data1)) {
                            validate82.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/format", keyword: "format", params: { format: "uri" }, message: 'must match format "uri"' }];
                            return false;
                          }
                        }
                      }
                    }
                  } else {
                    validate82.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.fetchCredentialRef !== void 0) {
                const _errs7 = errors;
                if (!validate57(data.fetchCredentialRef, { instancePath: instancePath + "/fetchCredentialRef", parentData: data, parentDataProperty: "fetchCredentialRef", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs7 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.reportCredentialRef !== void 0) {
                  const _errs8 = errors;
                  if (!validate57(data.reportCredentialRef, { instancePath: instancePath + "/reportCredentialRef", parentData: data, parentDataProperty: "reportCredentialRef", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs8 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.webhookSecretRef !== void 0) {
                    const _errs9 = errors;
                    if (!validate57(data.webhookSecretRef, { instancePath: instancePath + "/webhookSecretRef", parentData: data, parentDataProperty: "webhookSecretRef", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
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
    } else {
      validate82.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate82.errors = vErrors;
  return errors === 0;
}
validate82.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
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
      if (data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.spec === void 0 && (missing0 = "spec")) {
        validate80.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "name" || key0 === "spec")) {
            validate80.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
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
              let data1 = data.name;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (func1(data1) > 63) {
                    validate80.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
                    return false;
                  } else {
                    if (func1(data1) < 1) {
                      validate80.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                      return false;
                    } else {
                      if (!pattern6.test(data1)) {
                        validate80.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
                        return false;
                      }
                    }
                  }
                } else {
                  validate80.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.spec !== void 0) {
                const _errs5 = errors;
                if (!validate82(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate82.errors : vErrors.concat(validate82.errors);
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
      validate80.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate80.errors = vErrors;
  return errors === 0;
}
validate80.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var DependencyEgressPolicy = validate88;
function validate88(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate88.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate88.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "NONE")) {
    validate88.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema26.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate88.errors = vErrors;
  return errors === 0;
}
validate88.evaluated = { "dynamicProps": false, "dynamicItems": false };
var DevOpsProject = validate89;
var formats2 = require_formats().fullFormats["date-time"];
var pattern15 = new RegExp("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$", "u");
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
  if (errors === 0) {
    if (errors === 0) {
      if (typeof data === "string") {
        if (!pattern15.test(data)) {
          validate91.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$" }, message: 'must match pattern "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$"' }];
          return false;
        } else {
          if (!formats2.validate(data)) {
            validate91.errors = [{ instancePath, schemaPath: "#/format", keyword: "format", params: { format: "date-time" }, message: 'must match format "date-time"' }];
            return false;
          }
        }
      } else {
        validate91.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
        return false;
      }
    }
  }
  validate91.errors = vErrors;
  return errors === 0;
}
validate91.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate95(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate95.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (func1(data) > 128) {
        validate95.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate95.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern5.test(data)) {
            validate95.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"' }];
            return false;
          }
        }
      }
    } else {
      validate95.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate95.errors = vErrors;
  return errors === 0;
}
validate95.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate94(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate94.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.tenantId === void 0 && (missing0 = "tenantId")) {
        validate94.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "tenantId")) {
            validate94.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.tenantId !== void 0) {
            if (!validate95(data.tenantId, { instancePath: instancePath + "/tenantId", parentData: data, parentDataProperty: "tenantId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate95.errors : vErrors.concat(validate95.errors);
              errors = vErrors.length;
            }
          }
        }
      }
    } else {
      validate94.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate94.errors = vErrors;
  return errors === 0;
}
validate94.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.createdAt === void 0 && (missing0 = "createdAt") || data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.resourceVersion === void 0 && (missing0 = "resourceVersion") || data.scope === void 0 && (missing0 = "scope") || data.updatedAt === void 0 && (missing0 = "updatedAt")) {
        validate90.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "createdAt" || key0 === "id" || key0 === "name" || key0 === "resourceVersion" || key0 === "scope" || key0 === "updatedAt")) {
            validate90.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.createdAt !== void 0) {
            const _errs2 = errors;
            if (!validate91(data.createdAt, { instancePath: instancePath + "/createdAt", parentData: data, parentDataProperty: "createdAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
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
              if (data.name !== void 0) {
                let data2 = data.name;
                const _errs4 = errors;
                if (errors === _errs4) {
                  if (typeof data2 === "string") {
                    if (func1(data2) > 63) {
                      validate90.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
                      return false;
                    } else {
                      if (func1(data2) < 1) {
                        validate90.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                        return false;
                      } else {
                        if (!pattern6.test(data2)) {
                          validate90.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
                          return false;
                        }
                      }
                    }
                  } else {
                    validate90.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.resourceVersion !== void 0) {
                  let data3 = data.resourceVersion;
                  const _errs6 = errors;
                  if (!(typeof data3 == "number" && (!(data3 % 1) && !isNaN(data3)))) {
                    validate90.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                    return false;
                  }
                  if (errors === _errs6) {
                    if (typeof data3 == "number") {
                      if (data3 > 9007199254740991 || isNaN(data3)) {
                        validate90.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                        return false;
                      } else {
                        if (data3 < 1 || isNaN(data3)) {
                          validate90.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
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
                    if (!validate94(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate94.errors : vErrors.concat(validate94.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs8 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.updatedAt !== void 0) {
                      const _errs9 = errors;
                      if (!validate91(data.updatedAt, { instancePath: instancePath + "/updatedAt", parentData: data, parentDataProperty: "updatedAt", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
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
    } else {
      validate90.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate90.errors = vErrors;
  return errors === 0;
}
validate90.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata")) {
        validate89.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "kind" || key0 === "metadata")) {
            validate89.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
              validate89.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if ("DevOpsProject" !== data.kind) {
                validate89.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "DevOpsProject" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.metadata !== void 0) {
                const _errs4 = errors;
                if (!validate90(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate90.errors : vErrors.concat(validate90.errors);
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
      validate89.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate89.errors = vErrors;
  return errors === 0;
}
validate89.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var Pipeline = validate100;
var pattern18 = new RegExp("^sha256:[0-9a-f]{64}$", "u");
function validate101(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate101.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.contentDigest === void 0 && (missing0 = "contentDigest") || data.id === void 0 && (missing0 = "id") || data.revision === void 0 && (missing0 = "revision")) {
        validate101.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "contentDigest" || key0 === "id" || key0 === "revision")) {
            validate101.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.contentDigest !== void 0) {
            let data0 = data.contentDigest;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (typeof data0 === "string") {
                if (!pattern18.test(data0)) {
                  validate101.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                  return false;
                }
              } else {
                validate101.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.id !== void 0) {
              const _errs4 = errors;
              if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.revision !== void 0) {
                let data2 = data.revision;
                const _errs5 = errors;
                if (!(typeof data2 == "number" && (!(data2 % 1) && !isNaN(data2)))) {
                  validate101.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                  return false;
                }
                if (errors === _errs5) {
                  if (typeof data2 == "number") {
                    if (data2 > 9007199254740991 || isNaN(data2)) {
                      validate101.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                      return false;
                    } else {
                      if (data2 < 1 || isNaN(data2)) {
                        validate101.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                        return false;
                      }
                    }
                  }
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
      validate101.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate101.errors = vErrors;
  return errors === 0;
}
validate101.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate104(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate104.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.contentDigest === void 0 && (missing0 = "contentDigest") || data.spec === void 0 && (missing0 = "spec")) {
        validate104.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "contentDigest" || key0 === "spec")) {
            validate104.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.contentDigest !== void 0) {
            let data0 = data.contentDigest;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (typeof data0 === "string") {
                if (!pattern18.test(data0)) {
                  validate104.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                  return false;
                }
              } else {
                validate104.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.spec !== void 0) {
              const _errs4 = errors;
              if (!validate60(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
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
      validate104.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate104.errors = vErrors;
  return errors === 0;
}
validate104.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate100(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate100.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.draft === void 0 && (missing0 = "draft") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata") || data.projectId === void 0 && (missing0 = "projectId")) {
        validate100.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "activeRevision" || key0 === "apiVersion" || key0 === "draft" || key0 === "kind" || key0 === "metadata" || key0 === "projectId")) {
            validate100.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.activeRevision !== void 0) {
            const _errs2 = errors;
            if (!validate101(data.activeRevision, { instancePath: instancePath + "/activeRevision", parentData: data, parentDataProperty: "activeRevision", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate101.errors : vErrors.concat(validate101.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.apiVersion !== void 0) {
              const _errs3 = errors;
              if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
                validate100.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.draft !== void 0) {
                const _errs4 = errors;
                if (!validate104(data.draft, { instancePath: instancePath + "/draft", parentData: data, parentDataProperty: "draft", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate104.errors : vErrors.concat(validate104.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.kind !== void 0) {
                  const _errs5 = errors;
                  if ("Pipeline" !== data.kind) {
                    validate100.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "Pipeline" }, message: "must be equal to constant" }];
                    return false;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.metadata !== void 0) {
                    const _errs6 = errors;
                    if (!validate90(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate90.errors : vErrors.concat(validate90.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.projectId !== void 0) {
                      const _errs7 = errors;
                      if (!validate57(data.projectId, { instancePath: instancePath + "/projectId", parentData: data, parentDataProperty: "projectId", rootData, dynamicAnchors })) {
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
        }
      }
    } else {
      validate100.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate100.errors = vErrors;
  return errors === 0;
}
validate100.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineActivation = validate109;
var schema44 = { "additionalProperties": false, "properties": { "activatedAt": { "$ref": "#/components/schemas/Timestamp" }, "activatedBy": { "$ref": "#/components/schemas/SubjectRef" }, "apiVersion": { "const": "devops.matrix.xiak.com/v1" }, "contentDigest": { "pattern": "^sha256:[0-9a-f]{64}$", "type": "string" }, "id": { "$ref": "#/components/schemas/ResourceID" }, "kind": { "const": "PipelineRevision" }, "pipelineId": { "$ref": "#/components/schemas/ResourceID" }, "projectId": { "$ref": "#/components/schemas/ResourceID" }, "revision": { "maximum": 9007199254740991, "minimum": 1, "type": "integer" }, "scope": { "$ref": "#/components/schemas/ResourceScope" }, "spec": { "$ref": "#/components/schemas/PipelineRevisionSpec" } }, "required": ["activatedAt", "activatedBy", "apiVersion", "contentDigest", "id", "kind", "pipelineId", "projectId", "revision", "scope", "spec"], "type": "object" };
var func21 = Object.prototype.hasOwnProperty;
var schema46 = { "enum": ["USER", "SERVICE_ACCOUNT"], "type": "string" };
function validate114(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate114.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate114.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "USER" || data === "SERVICE_ACCOUNT")) {
    validate114.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema46.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate114.errors = vErrors;
  return errors === 0;
}
validate114.evaluated = { "dynamicProps": false, "dynamicItems": false };
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
      if (data.id === void 0 && (missing0 = "id") || data.kind === void 0 && (missing0 = "kind")) {
        validate113.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "kind")) {
            validate113.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (typeof data.id !== "string") {
              validate113.errors = [{ instancePath: instancePath + "/id", schemaPath: "#/properties/id/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs4 = errors;
              if (!validate114(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate114.errors : vErrors.concat(validate114.errors);
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
      validate113.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate113.errors = vErrors;
  return errors === 0;
}
validate113.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var schema47 = { "additionalProperties": false, "properties": { "dependencyEgress": { "$ref": "#/components/schemas/DependencyEgressPolicy" }, "executorProfile": { "const": "MATRIX_NATIVE_ISOLATED_V1" }, "limits": { "$ref": "#/components/schemas/VerificationLimits" }, "reporterPolicy": { "$ref": "#/components/schemas/ReporterPolicy" }, "repositoryBindingDigest": { "pattern": "^sha256:[0-9a-f]{64}$", "type": "string" }, "repositoryBindingId": { "$ref": "#/components/schemas/ResourceID" }, "steps": { "items": false, "maxItems": 2, "minItems": 2, "prefixItems": [{ "additionalProperties": false, "properties": { "kind": { "const": "GO_TEST" }, "ordinal": { "const": 1 } }, "required": ["kind", "ordinal"], "type": "object" }, { "additionalProperties": false, "properties": { "kind": { "const": "GO_VET" }, "ordinal": { "const": 2 } }, "required": ["kind", "ordinal"], "type": "object" }], "type": "array" }, "toolchainImageDigest": { "const": "sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3" }, "triggerPolicy": { "$ref": "#/components/schemas/TriggerPolicy" }, "verificationProfile": { "$ref": "#/components/schemas/VerificationProfile" } }, "required": ["dependencyEgress", "executorProfile", "limits", "reporterPolicy", "repositoryBindingDigest", "repositoryBindingId", "steps", "toolchainImageDigest", "triggerPolicy", "verificationProfile"], "type": "object" };
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.cpuMillis === void 0 && (missing0 = "cpuMillis") || data.maxLogBytes === void 0 && (missing0 = "maxLogBytes") || data.memoryBytes === void 0 && (missing0 = "memoryBytes") || data.processLimit === void 0 && (missing0 = "processLimit") || data.runTimeoutSeconds === void 0 && (missing0 = "runTimeoutSeconds") || data.stepTimeoutSeconds === void 0 && (missing0 = "stepTimeoutSeconds") || data.writableBytes === void 0 && (missing0 = "writableBytes")) {
        validate123.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "cpuMillis" || key0 === "maxLogBytes" || key0 === "memoryBytes" || key0 === "processLimit" || key0 === "runTimeoutSeconds" || key0 === "stepTimeoutSeconds" || key0 === "writableBytes")) {
            validate123.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.cpuMillis !== void 0) {
            const _errs2 = errors;
            if (2e3 !== data.cpuMillis) {
              validate123.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/const", keyword: "const", params: { allowedValue: 2e3 }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.maxLogBytes !== void 0) {
              const _errs3 = errors;
              if (8388608 !== data.maxLogBytes) {
                validate123.errors = [{ instancePath: instancePath + "/maxLogBytes", schemaPath: "#/properties/maxLogBytes/const", keyword: "const", params: { allowedValue: 8388608 }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.memoryBytes !== void 0) {
                const _errs4 = errors;
                if (2147483648 !== data.memoryBytes) {
                  validate123.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/const", keyword: "const", params: { allowedValue: 2147483648 }, message: "must be equal to constant" }];
                  return false;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.processLimit !== void 0) {
                  const _errs5 = errors;
                  if (256 !== data.processLimit) {
                    validate123.errors = [{ instancePath: instancePath + "/processLimit", schemaPath: "#/properties/processLimit/const", keyword: "const", params: { allowedValue: 256 }, message: "must be equal to constant" }];
                    return false;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.runTimeoutSeconds !== void 0) {
                    const _errs6 = errors;
                    if (1200 !== data.runTimeoutSeconds) {
                      validate123.errors = [{ instancePath: instancePath + "/runTimeoutSeconds", schemaPath: "#/properties/runTimeoutSeconds/const", keyword: "const", params: { allowedValue: 1200 }, message: "must be equal to constant" }];
                      return false;
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.stepTimeoutSeconds !== void 0) {
                      const _errs7 = errors;
                      if (600 !== data.stepTimeoutSeconds) {
                        validate123.errors = [{ instancePath: instancePath + "/stepTimeoutSeconds", schemaPath: "#/properties/stepTimeoutSeconds/const", keyword: "const", params: { allowedValue: 600 }, message: "must be equal to constant" }];
                        return false;
                      }
                      var valid0 = _errs7 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.writableBytes !== void 0) {
                        const _errs8 = errors;
                        if (2147483648 !== data.writableBytes) {
                          validate123.errors = [{ instancePath: instancePath + "/writableBytes", schemaPath: "#/properties/writableBytes/const", keyword: "const", params: { allowedValue: 2147483648 }, message: "must be equal to constant" }];
                          return false;
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
function validate121(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate121.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.dependencyEgress === void 0 && (missing0 = "dependencyEgress") || data.executorProfile === void 0 && (missing0 = "executorProfile") || data.limits === void 0 && (missing0 = "limits") || data.reporterPolicy === void 0 && (missing0 = "reporterPolicy") || data.repositoryBindingDigest === void 0 && (missing0 = "repositoryBindingDigest") || data.repositoryBindingId === void 0 && (missing0 = "repositoryBindingId") || data.steps === void 0 && (missing0 = "steps") || data.toolchainImageDigest === void 0 && (missing0 = "toolchainImageDigest") || data.triggerPolicy === void 0 && (missing0 = "triggerPolicy") || data.verificationProfile === void 0 && (missing0 = "verificationProfile")) {
        validate121.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func21.call(schema47.properties, key0)) {
            validate121.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.dependencyEgress !== void 0) {
            const _errs2 = errors;
            if (!validate61(data.dependencyEgress, { instancePath: instancePath + "/dependencyEgress", parentData: data, parentDataProperty: "dependencyEgress", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate61.errors : vErrors.concat(validate61.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.executorProfile !== void 0) {
              const _errs3 = errors;
              if ("MATRIX_NATIVE_ISOLATED_V1" !== data.executorProfile) {
                validate121.errors = [{ instancePath: instancePath + "/executorProfile", schemaPath: "#/properties/executorProfile/const", keyword: "const", params: { allowedValue: "MATRIX_NATIVE_ISOLATED_V1" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.limits !== void 0) {
                const _errs4 = errors;
                if (!validate123(data.limits, { instancePath: instancePath + "/limits", parentData: data, parentDataProperty: "limits", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate123.errors : vErrors.concat(validate123.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.reporterPolicy !== void 0) {
                  const _errs5 = errors;
                  if (!validate63(data.reporterPolicy, { instancePath: instancePath + "/reporterPolicy", parentData: data, parentDataProperty: "reporterPolicy", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate63.errors : vErrors.concat(validate63.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.repositoryBindingDigest !== void 0) {
                    let data4 = data.repositoryBindingDigest;
                    const _errs6 = errors;
                    if (errors === _errs6) {
                      if (typeof data4 === "string") {
                        if (!pattern18.test(data4)) {
                          validate121.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                          return false;
                        }
                      } else {
                        validate121.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                        return false;
                      }
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.repositoryBindingId !== void 0) {
                      const _errs8 = errors;
                      if (!validate57(data.repositoryBindingId, { instancePath: instancePath + "/repositoryBindingId", parentData: data, parentDataProperty: "repositoryBindingId", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.steps !== void 0) {
                        let data6 = data.steps;
                        const _errs9 = errors;
                        if (errors === _errs9) {
                          if (Array.isArray(data6)) {
                            if (data6.length > 2) {
                              validate121.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/maxItems", keyword: "maxItems", params: { limit: 2 }, message: "must NOT have more than 2 items" }];
                              return false;
                            } else {
                              if (data6.length < 2) {
                                validate121.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/minItems", keyword: "minItems", params: { limit: 2 }, message: "must NOT have fewer than 2 items" }];
                                return false;
                              } else {
                                const len0 = data6.length;
                                if (len0 > 0) {
                                  let data7 = data6[0];
                                  const _errs11 = errors;
                                  if (errors === _errs11) {
                                    if (data7 && typeof data7 == "object" && !Array.isArray(data7)) {
                                      let missing1;
                                      if (data7.kind === void 0 && (missing1 = "kind") || data7.ordinal === void 0 && (missing1 = "ordinal")) {
                                        validate121.errors = [{ instancePath: instancePath + "/steps/0", schemaPath: "#/properties/steps/prefixItems/0/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
                                        return false;
                                      } else {
                                        const _errs13 = errors;
                                        for (const key1 in data7) {
                                          if (!(key1 === "kind" || key1 === "ordinal")) {
                                            validate121.errors = [{ instancePath: instancePath + "/steps/0", schemaPath: "#/properties/steps/prefixItems/0/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key1 }, message: "must NOT have additional properties" }];
                                            return false;
                                            break;
                                          }
                                        }
                                        if (_errs13 === errors) {
                                          if (data7.kind !== void 0) {
                                            const _errs14 = errors;
                                            if ("GO_TEST" !== data7.kind) {
                                              validate121.errors = [{ instancePath: instancePath + "/steps/0/kind", schemaPath: "#/properties/steps/prefixItems/0/properties/kind/const", keyword: "const", params: { allowedValue: "GO_TEST" }, message: "must be equal to constant" }];
                                              return false;
                                            }
                                            var valid2 = _errs14 === errors;
                                          } else {
                                            var valid2 = true;
                                          }
                                          if (valid2) {
                                            if (data7.ordinal !== void 0) {
                                              const _errs15 = errors;
                                              if (1 !== data7.ordinal) {
                                                validate121.errors = [{ instancePath: instancePath + "/steps/0/ordinal", schemaPath: "#/properties/steps/prefixItems/0/properties/ordinal/const", keyword: "const", params: { allowedValue: 1 }, message: "must be equal to constant" }];
                                                return false;
                                              }
                                              var valid2 = _errs15 === errors;
                                            } else {
                                              var valid2 = true;
                                            }
                                          }
                                        }
                                      }
                                    } else {
                                      validate121.errors = [{ instancePath: instancePath + "/steps/0", schemaPath: "#/properties/steps/prefixItems/0/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
                                      return false;
                                    }
                                  }
                                  var valid1 = _errs11 === errors;
                                }
                                if (valid1) {
                                  if (len0 > 1) {
                                    let data10 = data6[1];
                                    const _errs16 = errors;
                                    if (errors === _errs16) {
                                      if (data10 && typeof data10 == "object" && !Array.isArray(data10)) {
                                        let missing2;
                                        if (data10.kind === void 0 && (missing2 = "kind") || data10.ordinal === void 0 && (missing2 = "ordinal")) {
                                          validate121.errors = [{ instancePath: instancePath + "/steps/1", schemaPath: "#/properties/steps/prefixItems/1/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
                                          return false;
                                        } else {
                                          const _errs18 = errors;
                                          for (const key2 in data10) {
                                            if (!(key2 === "kind" || key2 === "ordinal")) {
                                              validate121.errors = [{ instancePath: instancePath + "/steps/1", schemaPath: "#/properties/steps/prefixItems/1/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key2 }, message: "must NOT have additional properties" }];
                                              return false;
                                              break;
                                            }
                                          }
                                          if (_errs18 === errors) {
                                            if (data10.kind !== void 0) {
                                              const _errs19 = errors;
                                              if ("GO_VET" !== data10.kind) {
                                                validate121.errors = [{ instancePath: instancePath + "/steps/1/kind", schemaPath: "#/properties/steps/prefixItems/1/properties/kind/const", keyword: "const", params: { allowedValue: "GO_VET" }, message: "must be equal to constant" }];
                                                return false;
                                              }
                                              var valid3 = _errs19 === errors;
                                            } else {
                                              var valid3 = true;
                                            }
                                            if (valid3) {
                                              if (data10.ordinal !== void 0) {
                                                const _errs20 = errors;
                                                if (2 !== data10.ordinal) {
                                                  validate121.errors = [{ instancePath: instancePath + "/steps/1/ordinal", schemaPath: "#/properties/steps/prefixItems/1/properties/ordinal/const", keyword: "const", params: { allowedValue: 2 }, message: "must be equal to constant" }];
                                                  return false;
                                                }
                                                var valid3 = _errs20 === errors;
                                              } else {
                                                var valid3 = true;
                                              }
                                            }
                                          }
                                        }
                                      } else {
                                        validate121.errors = [{ instancePath: instancePath + "/steps/1", schemaPath: "#/properties/steps/prefixItems/1/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
                                        return false;
                                      }
                                    }
                                    var valid1 = _errs16 === errors;
                                  }
                                  if (valid1) {
                                    const len1 = data6.length;
                                    if (!(len1 <= 2)) {
                                      validate121.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/items", keyword: "items", params: { limit: 2 }, message: "must NOT have more than 2 items" }];
                                      return false;
                                    }
                                  }
                                }
                              }
                            }
                          } else {
                            validate121.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                            return false;
                          }
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.toolchainImageDigest !== void 0) {
                          const _errs21 = errors;
                          if ("sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3" !== data.toolchainImageDigest) {
                            validate121.errors = [{ instancePath: instancePath + "/toolchainImageDigest", schemaPath: "#/properties/toolchainImageDigest/const", keyword: "const", params: { allowedValue: "sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3" }, message: "must be equal to constant" }];
                            return false;
                          }
                          var valid0 = _errs21 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.triggerPolicy !== void 0) {
                            const _errs22 = errors;
                            if (!validate66(data.triggerPolicy, { instancePath: instancePath + "/triggerPolicy", parentData: data, parentDataProperty: "triggerPolicy", rootData, dynamicAnchors })) {
                              vErrors = vErrors === null ? validate66.errors : vErrors.concat(validate66.errors);
                              errors = vErrors.length;
                            }
                            var valid0 = _errs22 === errors;
                          } else {
                            var valid0 = true;
                          }
                          if (valid0) {
                            if (data.verificationProfile !== void 0) {
                              const _errs23 = errors;
                              if (!validate68(data.verificationProfile, { instancePath: instancePath + "/verificationProfile", parentData: data, parentDataProperty: "verificationProfile", rootData, dynamicAnchors })) {
                                vErrors = vErrors === null ? validate68.errors : vErrors.concat(validate68.errors);
                                errors = vErrors.length;
                              }
                              var valid0 = _errs23 === errors;
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
    } else {
      validate121.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate121.errors = vErrors;
  return errors === 0;
}
validate121.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate111(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate111.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.activatedAt === void 0 && (missing0 = "activatedAt") || data.activatedBy === void 0 && (missing0 = "activatedBy") || data.apiVersion === void 0 && (missing0 = "apiVersion") || data.contentDigest === void 0 && (missing0 = "contentDigest") || data.id === void 0 && (missing0 = "id") || data.kind === void 0 && (missing0 = "kind") || data.pipelineId === void 0 && (missing0 = "pipelineId") || data.projectId === void 0 && (missing0 = "projectId") || data.revision === void 0 && (missing0 = "revision") || data.scope === void 0 && (missing0 = "scope") || data.spec === void 0 && (missing0 = "spec")) {
        validate111.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func21.call(schema44.properties, key0)) {
            validate111.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.activatedAt !== void 0) {
            const _errs2 = errors;
            if (!validate91(data.activatedAt, { instancePath: instancePath + "/activatedAt", parentData: data, parentDataProperty: "activatedAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.activatedBy !== void 0) {
              const _errs3 = errors;
              if (!validate113(data.activatedBy, { instancePath: instancePath + "/activatedBy", parentData: data, parentDataProperty: "activatedBy", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate113.errors : vErrors.concat(validate113.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.apiVersion !== void 0) {
                const _errs4 = errors;
                if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
                  validate111.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
                  return false;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.contentDigest !== void 0) {
                  let data3 = data.contentDigest;
                  const _errs5 = errors;
                  if (errors === _errs5) {
                    if (typeof data3 === "string") {
                      if (!pattern18.test(data3)) {
                        validate111.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                        return false;
                      }
                    } else {
                      validate111.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                      return false;
                    }
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.id !== void 0) {
                    const _errs7 = errors;
                    if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs7 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.kind !== void 0) {
                      const _errs8 = errors;
                      if ("PipelineRevision" !== data.kind) {
                        validate111.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "PipelineRevision" }, message: "must be equal to constant" }];
                        return false;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.pipelineId !== void 0) {
                        const _errs9 = errors;
                        if (!validate57(data.pipelineId, { instancePath: instancePath + "/pipelineId", parentData: data, parentDataProperty: "pipelineId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.projectId !== void 0) {
                          const _errs10 = errors;
                          if (!validate57(data.projectId, { instancePath: instancePath + "/projectId", parentData: data, parentDataProperty: "projectId", rootData, dynamicAnchors })) {
                            vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                            errors = vErrors.length;
                          }
                          var valid0 = _errs10 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.revision !== void 0) {
                            let data8 = data.revision;
                            const _errs11 = errors;
                            if (!(typeof data8 == "number" && (!(data8 % 1) && !isNaN(data8)))) {
                              validate111.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                              return false;
                            }
                            if (errors === _errs11) {
                              if (typeof data8 == "number") {
                                if (data8 > 9007199254740991 || isNaN(data8)) {
                                  validate111.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                                  return false;
                                } else {
                                  if (data8 < 1 || isNaN(data8)) {
                                    validate111.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                                    return false;
                                  }
                                }
                              }
                            }
                            var valid0 = _errs11 === errors;
                          } else {
                            var valid0 = true;
                          }
                          if (valid0) {
                            if (data.scope !== void 0) {
                              const _errs13 = errors;
                              if (!validate94(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                                vErrors = vErrors === null ? validate94.errors : vErrors.concat(validate94.errors);
                                errors = vErrors.length;
                              }
                              var valid0 = _errs13 === errors;
                            } else {
                              var valid0 = true;
                            }
                            if (valid0) {
                              if (data.spec !== void 0) {
                                const _errs14 = errors;
                                if (!validate121(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                                  vErrors = vErrors === null ? validate121.errors : vErrors.concat(validate121.errors);
                                  errors = vErrors.length;
                                }
                                var valid0 = _errs14 === errors;
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
    } else {
      validate111.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate111.errors = vErrors;
  return errors === 0;
}
validate111.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate109(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate109.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.pipeline === void 0 && (missing0 = "pipeline") || data.revision === void 0 && (missing0 = "revision")) {
        validate109.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "kind" || key0 === "pipeline" || key0 === "revision")) {
            validate109.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
              validate109.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if ("PipelineActivation" !== data.kind) {
                validate109.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "PipelineActivation" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.pipeline !== void 0) {
                const _errs4 = errors;
                if (!validate100(data.pipeline, { instancePath: instancePath + "/pipeline", parentData: data, parentDataProperty: "pipeline", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate100.errors : vErrors.concat(validate100.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.revision !== void 0) {
                  let data3 = data.revision;
                  const _errs5 = errors;
                  if (!validate111(data3, { instancePath: instancePath + "/revision", parentData: data, parentDataProperty: "revision", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate111.errors : vErrors.concat(validate111.errors);
                    errors = vErrors.length;
                  }
                  if (errors === _errs5) {
                    if (typeof data3 == "number") {
                      if (data3 > 9007199254740991 || isNaN(data3)) {
                        validate109.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                        return false;
                      } else {
                        if (data3 < 1 || isNaN(data3)) {
                          validate109.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                          return false;
                        }
                      }
                    }
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
      validate109.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate109.errors = vErrors;
  return errors === 0;
}
validate109.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineDraft = validate131;
function validate131(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate131.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.contentDigest === void 0 && (missing0 = "contentDigest") || data.spec === void 0 && (missing0 = "spec")) {
        validate131.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "contentDigest" || key0 === "spec")) {
            validate131.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.contentDigest !== void 0) {
            let data0 = data.contentDigest;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (typeof data0 === "string") {
                if (!pattern18.test(data0)) {
                  validate131.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                  return false;
                }
              } else {
                validate131.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.spec !== void 0) {
              const _errs4 = errors;
              if (!validate60(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
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
      validate131.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate131.errors = vErrors;
  return errors === 0;
}
validate131.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineDraftSpec = validate133;
function validate133(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate133.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.dependencyEgress === void 0 && (missing0 = "dependencyEgress") || data.reporterPolicy === void 0 && (missing0 = "reporterPolicy") || data.repositoryBindingId === void 0 && (missing0 = "repositoryBindingId") || data.triggerPolicy === void 0 && (missing0 = "triggerPolicy") || data.verificationProfile === void 0 && (missing0 = "verificationProfile")) {
        validate133.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "dependencyEgress" || key0 === "reporterPolicy" || key0 === "repositoryBindingId" || key0 === "triggerPolicy" || key0 === "verificationProfile")) {
            validate133.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.dependencyEgress !== void 0) {
            const _errs2 = errors;
            if (!validate61(data.dependencyEgress, { instancePath: instancePath + "/dependencyEgress", parentData: data, parentDataProperty: "dependencyEgress", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate61.errors : vErrors.concat(validate61.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.reporterPolicy !== void 0) {
              const _errs3 = errors;
              if (!validate63(data.reporterPolicy, { instancePath: instancePath + "/reporterPolicy", parentData: data, parentDataProperty: "reporterPolicy", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate63.errors : vErrors.concat(validate63.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.repositoryBindingId !== void 0) {
                const _errs4 = errors;
                if (!validate57(data.repositoryBindingId, { instancePath: instancePath + "/repositoryBindingId", parentData: data, parentDataProperty: "repositoryBindingId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.triggerPolicy !== void 0) {
                  const _errs5 = errors;
                  if (!validate66(data.triggerPolicy, { instancePath: instancePath + "/triggerPolicy", parentData: data, parentDataProperty: "triggerPolicy", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate66.errors : vErrors.concat(validate66.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.verificationProfile !== void 0) {
                    const _errs6 = errors;
                    if (!validate68(data.verificationProfile, { instancePath: instancePath + "/verificationProfile", parentData: data, parentDataProperty: "verificationProfile", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate68.errors : vErrors.concat(validate68.errors);
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
      }
    } else {
      validate133.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate133.errors = vErrors;
  return errors === 0;
}
validate133.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRevision = validate139;
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
      if (data.activatedAt === void 0 && (missing0 = "activatedAt") || data.activatedBy === void 0 && (missing0 = "activatedBy") || data.apiVersion === void 0 && (missing0 = "apiVersion") || data.contentDigest === void 0 && (missing0 = "contentDigest") || data.id === void 0 && (missing0 = "id") || data.kind === void 0 && (missing0 = "kind") || data.pipelineId === void 0 && (missing0 = "pipelineId") || data.projectId === void 0 && (missing0 = "projectId") || data.revision === void 0 && (missing0 = "revision") || data.scope === void 0 && (missing0 = "scope") || data.spec === void 0 && (missing0 = "spec")) {
        validate139.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func21.call(schema44.properties, key0)) {
            validate139.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.activatedAt !== void 0) {
            const _errs2 = errors;
            if (!validate91(data.activatedAt, { instancePath: instancePath + "/activatedAt", parentData: data, parentDataProperty: "activatedAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.activatedBy !== void 0) {
              const _errs3 = errors;
              if (!validate113(data.activatedBy, { instancePath: instancePath + "/activatedBy", parentData: data, parentDataProperty: "activatedBy", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate113.errors : vErrors.concat(validate113.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.apiVersion !== void 0) {
                const _errs4 = errors;
                if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
                  validate139.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
                  return false;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.contentDigest !== void 0) {
                  let data3 = data.contentDigest;
                  const _errs5 = errors;
                  if (errors === _errs5) {
                    if (typeof data3 === "string") {
                      if (!pattern18.test(data3)) {
                        validate139.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                        return false;
                      }
                    } else {
                      validate139.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                      return false;
                    }
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.id !== void 0) {
                    const _errs7 = errors;
                    if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs7 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.kind !== void 0) {
                      const _errs8 = errors;
                      if ("PipelineRevision" !== data.kind) {
                        validate139.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "PipelineRevision" }, message: "must be equal to constant" }];
                        return false;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.pipelineId !== void 0) {
                        const _errs9 = errors;
                        if (!validate57(data.pipelineId, { instancePath: instancePath + "/pipelineId", parentData: data, parentDataProperty: "pipelineId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.projectId !== void 0) {
                          const _errs10 = errors;
                          if (!validate57(data.projectId, { instancePath: instancePath + "/projectId", parentData: data, parentDataProperty: "projectId", rootData, dynamicAnchors })) {
                            vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                            errors = vErrors.length;
                          }
                          var valid0 = _errs10 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.revision !== void 0) {
                            let data8 = data.revision;
                            const _errs11 = errors;
                            if (!(typeof data8 == "number" && (!(data8 % 1) && !isNaN(data8)))) {
                              validate139.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                              return false;
                            }
                            if (errors === _errs11) {
                              if (typeof data8 == "number") {
                                if (data8 > 9007199254740991 || isNaN(data8)) {
                                  validate139.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                                  return false;
                                } else {
                                  if (data8 < 1 || isNaN(data8)) {
                                    validate139.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                                    return false;
                                  }
                                }
                              }
                            }
                            var valid0 = _errs11 === errors;
                          } else {
                            var valid0 = true;
                          }
                          if (valid0) {
                            if (data.scope !== void 0) {
                              const _errs13 = errors;
                              if (!validate94(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                                vErrors = vErrors === null ? validate94.errors : vErrors.concat(validate94.errors);
                                errors = vErrors.length;
                              }
                              var valid0 = _errs13 === errors;
                            } else {
                              var valid0 = true;
                            }
                            if (valid0) {
                              if (data.spec !== void 0) {
                                const _errs14 = errors;
                                if (!validate121(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                                  vErrors = vErrors === null ? validate121.errors : vErrors.concat(validate121.errors);
                                  errors = vErrors.length;
                                }
                                var valid0 = _errs14 === errors;
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
    } else {
      validate139.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate139.errors = vErrors;
  return errors === 0;
}
validate139.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRevisionReference = validate147;
function validate147(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate147.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.contentDigest === void 0 && (missing0 = "contentDigest") || data.id === void 0 && (missing0 = "id") || data.revision === void 0 && (missing0 = "revision")) {
        validate147.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "contentDigest" || key0 === "id" || key0 === "revision")) {
            validate147.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.contentDigest !== void 0) {
            let data0 = data.contentDigest;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (typeof data0 === "string") {
                if (!pattern18.test(data0)) {
                  validate147.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                  return false;
                }
              } else {
                validate147.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.id !== void 0) {
              const _errs4 = errors;
              if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.revision !== void 0) {
                let data2 = data.revision;
                const _errs5 = errors;
                if (!(typeof data2 == "number" && (!(data2 % 1) && !isNaN(data2)))) {
                  validate147.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                  return false;
                }
                if (errors === _errs5) {
                  if (typeof data2 == "number") {
                    if (data2 > 9007199254740991 || isNaN(data2)) {
                      validate147.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                      return false;
                    } else {
                      if (data2 < 1 || isNaN(data2)) {
                        validate147.errors = [{ instancePath: instancePath + "/revision", schemaPath: "#/properties/revision/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                        return false;
                      }
                    }
                  }
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
      validate147.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate147.errors = vErrors;
  return errors === 0;
}
validate147.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRevisionSpec = validate149;
function validate149(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate149.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.dependencyEgress === void 0 && (missing0 = "dependencyEgress") || data.executorProfile === void 0 && (missing0 = "executorProfile") || data.limits === void 0 && (missing0 = "limits") || data.reporterPolicy === void 0 && (missing0 = "reporterPolicy") || data.repositoryBindingDigest === void 0 && (missing0 = "repositoryBindingDigest") || data.repositoryBindingId === void 0 && (missing0 = "repositoryBindingId") || data.steps === void 0 && (missing0 = "steps") || data.toolchainImageDigest === void 0 && (missing0 = "toolchainImageDigest") || data.triggerPolicy === void 0 && (missing0 = "triggerPolicy") || data.verificationProfile === void 0 && (missing0 = "verificationProfile")) {
        validate149.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func21.call(schema47.properties, key0)) {
            validate149.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.dependencyEgress !== void 0) {
            const _errs2 = errors;
            if (!validate61(data.dependencyEgress, { instancePath: instancePath + "/dependencyEgress", parentData: data, parentDataProperty: "dependencyEgress", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate61.errors : vErrors.concat(validate61.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.executorProfile !== void 0) {
              const _errs3 = errors;
              if ("MATRIX_NATIVE_ISOLATED_V1" !== data.executorProfile) {
                validate149.errors = [{ instancePath: instancePath + "/executorProfile", schemaPath: "#/properties/executorProfile/const", keyword: "const", params: { allowedValue: "MATRIX_NATIVE_ISOLATED_V1" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.limits !== void 0) {
                const _errs4 = errors;
                if (!validate123(data.limits, { instancePath: instancePath + "/limits", parentData: data, parentDataProperty: "limits", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate123.errors : vErrors.concat(validate123.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.reporterPolicy !== void 0) {
                  const _errs5 = errors;
                  if (!validate63(data.reporterPolicy, { instancePath: instancePath + "/reporterPolicy", parentData: data, parentDataProperty: "reporterPolicy", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate63.errors : vErrors.concat(validate63.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.repositoryBindingDigest !== void 0) {
                    let data4 = data.repositoryBindingDigest;
                    const _errs6 = errors;
                    if (errors === _errs6) {
                      if (typeof data4 === "string") {
                        if (!pattern18.test(data4)) {
                          validate149.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                          return false;
                        }
                      } else {
                        validate149.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                        return false;
                      }
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.repositoryBindingId !== void 0) {
                      const _errs8 = errors;
                      if (!validate57(data.repositoryBindingId, { instancePath: instancePath + "/repositoryBindingId", parentData: data, parentDataProperty: "repositoryBindingId", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.steps !== void 0) {
                        let data6 = data.steps;
                        const _errs9 = errors;
                        if (errors === _errs9) {
                          if (Array.isArray(data6)) {
                            if (data6.length > 2) {
                              validate149.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/maxItems", keyword: "maxItems", params: { limit: 2 }, message: "must NOT have more than 2 items" }];
                              return false;
                            } else {
                              if (data6.length < 2) {
                                validate149.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/minItems", keyword: "minItems", params: { limit: 2 }, message: "must NOT have fewer than 2 items" }];
                                return false;
                              } else {
                                const len0 = data6.length;
                                if (len0 > 0) {
                                  let data7 = data6[0];
                                  const _errs11 = errors;
                                  if (errors === _errs11) {
                                    if (data7 && typeof data7 == "object" && !Array.isArray(data7)) {
                                      let missing1;
                                      if (data7.kind === void 0 && (missing1 = "kind") || data7.ordinal === void 0 && (missing1 = "ordinal")) {
                                        validate149.errors = [{ instancePath: instancePath + "/steps/0", schemaPath: "#/properties/steps/prefixItems/0/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
                                        return false;
                                      } else {
                                        const _errs13 = errors;
                                        for (const key1 in data7) {
                                          if (!(key1 === "kind" || key1 === "ordinal")) {
                                            validate149.errors = [{ instancePath: instancePath + "/steps/0", schemaPath: "#/properties/steps/prefixItems/0/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key1 }, message: "must NOT have additional properties" }];
                                            return false;
                                            break;
                                          }
                                        }
                                        if (_errs13 === errors) {
                                          if (data7.kind !== void 0) {
                                            const _errs14 = errors;
                                            if ("GO_TEST" !== data7.kind) {
                                              validate149.errors = [{ instancePath: instancePath + "/steps/0/kind", schemaPath: "#/properties/steps/prefixItems/0/properties/kind/const", keyword: "const", params: { allowedValue: "GO_TEST" }, message: "must be equal to constant" }];
                                              return false;
                                            }
                                            var valid2 = _errs14 === errors;
                                          } else {
                                            var valid2 = true;
                                          }
                                          if (valid2) {
                                            if (data7.ordinal !== void 0) {
                                              const _errs15 = errors;
                                              if (1 !== data7.ordinal) {
                                                validate149.errors = [{ instancePath: instancePath + "/steps/0/ordinal", schemaPath: "#/properties/steps/prefixItems/0/properties/ordinal/const", keyword: "const", params: { allowedValue: 1 }, message: "must be equal to constant" }];
                                                return false;
                                              }
                                              var valid2 = _errs15 === errors;
                                            } else {
                                              var valid2 = true;
                                            }
                                          }
                                        }
                                      }
                                    } else {
                                      validate149.errors = [{ instancePath: instancePath + "/steps/0", schemaPath: "#/properties/steps/prefixItems/0/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
                                      return false;
                                    }
                                  }
                                  var valid1 = _errs11 === errors;
                                }
                                if (valid1) {
                                  if (len0 > 1) {
                                    let data10 = data6[1];
                                    const _errs16 = errors;
                                    if (errors === _errs16) {
                                      if (data10 && typeof data10 == "object" && !Array.isArray(data10)) {
                                        let missing2;
                                        if (data10.kind === void 0 && (missing2 = "kind") || data10.ordinal === void 0 && (missing2 = "ordinal")) {
                                          validate149.errors = [{ instancePath: instancePath + "/steps/1", schemaPath: "#/properties/steps/prefixItems/1/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
                                          return false;
                                        } else {
                                          const _errs18 = errors;
                                          for (const key2 in data10) {
                                            if (!(key2 === "kind" || key2 === "ordinal")) {
                                              validate149.errors = [{ instancePath: instancePath + "/steps/1", schemaPath: "#/properties/steps/prefixItems/1/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key2 }, message: "must NOT have additional properties" }];
                                              return false;
                                              break;
                                            }
                                          }
                                          if (_errs18 === errors) {
                                            if (data10.kind !== void 0) {
                                              const _errs19 = errors;
                                              if ("GO_VET" !== data10.kind) {
                                                validate149.errors = [{ instancePath: instancePath + "/steps/1/kind", schemaPath: "#/properties/steps/prefixItems/1/properties/kind/const", keyword: "const", params: { allowedValue: "GO_VET" }, message: "must be equal to constant" }];
                                                return false;
                                              }
                                              var valid3 = _errs19 === errors;
                                            } else {
                                              var valid3 = true;
                                            }
                                            if (valid3) {
                                              if (data10.ordinal !== void 0) {
                                                const _errs20 = errors;
                                                if (2 !== data10.ordinal) {
                                                  validate149.errors = [{ instancePath: instancePath + "/steps/1/ordinal", schemaPath: "#/properties/steps/prefixItems/1/properties/ordinal/const", keyword: "const", params: { allowedValue: 2 }, message: "must be equal to constant" }];
                                                  return false;
                                                }
                                                var valid3 = _errs20 === errors;
                                              } else {
                                                var valid3 = true;
                                              }
                                            }
                                          }
                                        }
                                      } else {
                                        validate149.errors = [{ instancePath: instancePath + "/steps/1", schemaPath: "#/properties/steps/prefixItems/1/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
                                        return false;
                                      }
                                    }
                                    var valid1 = _errs16 === errors;
                                  }
                                  if (valid1) {
                                    const len1 = data6.length;
                                    if (!(len1 <= 2)) {
                                      validate149.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/items", keyword: "items", params: { limit: 2 }, message: "must NOT have more than 2 items" }];
                                      return false;
                                    }
                                  }
                                }
                              }
                            }
                          } else {
                            validate149.errors = [{ instancePath: instancePath + "/steps", schemaPath: "#/properties/steps/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                            return false;
                          }
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.toolchainImageDigest !== void 0) {
                          const _errs21 = errors;
                          if ("sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3" !== data.toolchainImageDigest) {
                            validate149.errors = [{ instancePath: instancePath + "/toolchainImageDigest", schemaPath: "#/properties/toolchainImageDigest/const", keyword: "const", params: { allowedValue: "sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3" }, message: "must be equal to constant" }];
                            return false;
                          }
                          var valid0 = _errs21 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.triggerPolicy !== void 0) {
                            const _errs22 = errors;
                            if (!validate66(data.triggerPolicy, { instancePath: instancePath + "/triggerPolicy", parentData: data, parentDataProperty: "triggerPolicy", rootData, dynamicAnchors })) {
                              vErrors = vErrors === null ? validate66.errors : vErrors.concat(validate66.errors);
                              errors = vErrors.length;
                            }
                            var valid0 = _errs22 === errors;
                          } else {
                            var valid0 = true;
                          }
                          if (valid0) {
                            if (data.verificationProfile !== void 0) {
                              const _errs23 = errors;
                              if (!validate68(data.verificationProfile, { instancePath: instancePath + "/verificationProfile", parentData: data, parentDataProperty: "verificationProfile", rootData, dynamicAnchors })) {
                                vErrors = vErrors === null ? validate68.errors : vErrors.concat(validate68.errors);
                                errors = vErrors.length;
                              }
                              var valid0 = _errs23 === errors;
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
    } else {
      validate149.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate149.errors = vErrors;
  return errors === 0;
}
validate149.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRun = validate156;
var schema54 = { "additionalProperties": false, "properties": { "apiVersion": { "const": "devops.matrix.xiak.com/v1" }, "createdAt": { "$ref": "#/components/schemas/Timestamp" }, "id": { "$ref": "#/components/schemas/ResourceID" }, "input": { "$ref": "#/components/schemas/PipelineRunInput" }, "inputDigest": { "pattern": "^sha256:[0-9a-f]{64}$", "type": "string" }, "kind": { "const": "PipelineRun" }, "pipelineId": { "$ref": "#/components/schemas/ResourceID" }, "projectId": { "$ref": "#/components/schemas/ResourceID" }, "replay": { "$ref": "#/components/schemas/PipelineRunReplay" }, "scope": { "$ref": "#/components/schemas/ResourceScope" }, "status": { "$ref": "#/components/schemas/PipelineRunStatus" }, "updatedAt": { "$ref": "#/components/schemas/Timestamp" } }, "required": ["apiVersion", "createdAt", "id", "input", "inputDigest", "kind", "pipelineId", "projectId", "scope", "status", "updatedAt"], "type": "object" };
function validate159(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate159.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.change === void 0 && (missing0 = "change") || data.pipelineRevisionDigest === void 0 && (missing0 = "pipelineRevisionDigest") || data.pipelineRevisionId === void 0 && (missing0 = "pipelineRevisionId") || data.repositoryBindingDigest === void 0 && (missing0 = "repositoryBindingDigest") || data.repositoryBindingId === void 0 && (missing0 = "repositoryBindingId") || data.sourceEventDigest === void 0 && (missing0 = "sourceEventDigest") || data.sourceEventId === void 0 && (missing0 = "sourceEventId")) {
        validate159.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "change" || key0 === "pipelineRevisionDigest" || key0 === "pipelineRevisionId" || key0 === "repositoryBindingDigest" || key0 === "repositoryBindingId" || key0 === "sourceEventDigest" || key0 === "sourceEventId")) {
            validate159.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.change !== void 0) {
            const _errs2 = errors;
            if (!validate54(data.change, { instancePath: instancePath + "/change", parentData: data, parentDataProperty: "change", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.pipelineRevisionDigest !== void 0) {
              let data1 = data.pipelineRevisionDigest;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (!pattern18.test(data1)) {
                    validate159.errors = [{ instancePath: instancePath + "/pipelineRevisionDigest", schemaPath: "#/properties/pipelineRevisionDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                    return false;
                  }
                } else {
                  validate159.errors = [{ instancePath: instancePath + "/pipelineRevisionDigest", schemaPath: "#/properties/pipelineRevisionDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.pipelineRevisionId !== void 0) {
                const _errs5 = errors;
                if (!validate57(data.pipelineRevisionId, { instancePath: instancePath + "/pipelineRevisionId", parentData: data, parentDataProperty: "pipelineRevisionId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.repositoryBindingDigest !== void 0) {
                  let data3 = data.repositoryBindingDigest;
                  const _errs6 = errors;
                  if (errors === _errs6) {
                    if (typeof data3 === "string") {
                      if (!pattern18.test(data3)) {
                        validate159.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                        return false;
                      }
                    } else {
                      validate159.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                      return false;
                    }
                  }
                  var valid0 = _errs6 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.repositoryBindingId !== void 0) {
                    const _errs8 = errors;
                    if (!validate57(data.repositoryBindingId, { instancePath: instancePath + "/repositoryBindingId", parentData: data, parentDataProperty: "repositoryBindingId", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs8 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.sourceEventDigest !== void 0) {
                      let data5 = data.sourceEventDigest;
                      const _errs9 = errors;
                      if (errors === _errs9) {
                        if (typeof data5 === "string") {
                          if (!pattern18.test(data5)) {
                            validate159.errors = [{ instancePath: instancePath + "/sourceEventDigest", schemaPath: "#/properties/sourceEventDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                            return false;
                          }
                        } else {
                          validate159.errors = [{ instancePath: instancePath + "/sourceEventDigest", schemaPath: "#/properties/sourceEventDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                          return false;
                        }
                      }
                      var valid0 = _errs9 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.sourceEventId !== void 0) {
                        const _errs11 = errors;
                        if (!validate57(data.sourceEventId, { instancePath: instancePath + "/sourceEventId", parentData: data, parentDataProperty: "sourceEventId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
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
    } else {
      validate159.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate159.errors = vErrors;
  return errors === 0;
}
validate159.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var pattern30 = new RegExp("^operation-[0-9a-f]{64}$", "u");
var pattern31 = new RegExp("^pipeline-run-[0-9a-f]{48}$", "u");
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.commandId === void 0 && (missing0 = "commandId") || data.requestedBy === void 0 && (missing0 = "requestedBy") || data.sourceRunId === void 0 && (missing0 = "sourceRunId")) {
        validate167.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "commandId" || key0 === "requestedBy" || key0 === "sourceRunId")) {
            validate167.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.commandId !== void 0) {
            let data0 = data.commandId;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (typeof data0 === "string") {
                if (!pattern30.test(data0)) {
                  validate167.errors = [{ instancePath: instancePath + "/commandId", schemaPath: "#/properties/commandId/pattern", keyword: "pattern", params: { pattern: "^operation-[0-9a-f]{64}$" }, message: 'must match pattern "^operation-[0-9a-f]{64}$"' }];
                  return false;
                }
              } else {
                validate167.errors = [{ instancePath: instancePath + "/commandId", schemaPath: "#/properties/commandId/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.requestedBy !== void 0) {
              const _errs4 = errors;
              if (!validate113(data.requestedBy, { instancePath: instancePath + "/requestedBy", parentData: data, parentDataProperty: "requestedBy", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate113.errors : vErrors.concat(validate113.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.sourceRunId !== void 0) {
                let data2 = data.sourceRunId;
                const _errs5 = errors;
                if (errors === _errs5) {
                  if (typeof data2 === "string") {
                    if (!pattern31.test(data2)) {
                      validate167.errors = [{ instancePath: instancePath + "/sourceRunId", schemaPath: "#/properties/sourceRunId/pattern", keyword: "pattern", params: { pattern: "^pipeline-run-[0-9a-f]{48}$" }, message: 'must match pattern "^pipeline-run-[0-9a-f]{48}$"' }];
                      return false;
                    }
                  } else {
                    validate167.errors = [{ instancePath: instancePath + "/sourceRunId", schemaPath: "#/properties/sourceRunId/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
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
      validate167.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate167.errors = vErrors;
  return errors === 0;
}
validate167.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var schema57 = { "additionalProperties": false, "allOf": [{ "if": { "properties": { "state": { "const": "QUEUED" } }, "required": ["state"] }, "then": { "not": { "required": ["completedAt"] }, "properties": { "cancellationRequestedAt": false, "reason": { "enum": ["EVENT_ADMITTED"] }, "resourceVersion": { "const": 1 }, "stage": { "enum": ["RECEIVE"] } }, "required": ["reason"] } }, { "if": { "properties": { "state": { "const": "FETCHING" } }, "required": ["state"] }, "then": { "not": { "anyOf": [{ "required": ["reason"] }, { "required": ["completedAt"] }] }, "properties": { "stage": { "enum": ["FETCH"] } } } }, { "if": { "properties": { "state": { "const": "VERIFYING" } }, "required": ["state"] }, "then": { "not": { "anyOf": [{ "required": ["reason"] }, { "required": ["completedAt"] }] }, "properties": { "stage": { "enum": ["VERIFY"] } } } }, { "if": { "properties": { "state": { "const": "REPORTING" } }, "required": ["state"] }, "then": { "not": { "anyOf": [{ "required": ["reason"] }, { "required": ["completedAt"] }] }, "properties": { "stage": { "enum": ["REPORT"] } } } }, { "if": { "properties": { "state": { "const": "SUCCEEDED" } }, "required": ["state"] }, "then": { "properties": { "reason": { "enum": ["COMPLETED"] }, "stage": { "enum": ["REPORT"] } }, "required": ["reason", "completedAt"] } }, { "if": { "properties": { "state": { "const": "FAILED" } }, "required": ["state"] }, "then": { "properties": { "reason": { "enum": ["SOURCE_UNAVAILABLE", "COMMIT_MISMATCH", "EXECUTOR_UNAVAILABLE", "VERIFICATION_FAILED", "DEADLINE_EXCEEDED", "REPORT_UNAVAILABLE", "REPORT_CONFLICT"] }, "stage": { "enum": ["RECEIVE", "FETCH", "VERIFY", "REPORT"] } }, "required": ["reason", "completedAt"] } }, { "if": { "properties": { "state": { "const": "CANCELLED" } }, "required": ["state"] }, "then": { "properties": { "reason": { "enum": ["CANCELLED"] }, "stage": { "enum": ["RECEIVE", "FETCH", "VERIFY", "REPORT"] } }, "required": ["reason", "cancellationRequestedAt", "completedAt"] } }, { "if": { "properties": { "state": { "const": "RECONCILING" } }, "required": ["state"] }, "then": { "not": { "required": ["completedAt"] }, "properties": { "reason": { "enum": ["EXTERNAL_EFFECT_UNCERTAIN"] }, "stage": { "enum": ["REPORT"] } }, "required": ["reason"] } }, { "if": { "properties": { "state": { "const": "MANUAL_INTERVENTION" } }, "required": ["state"] }, "then": { "properties": { "reason": { "enum": ["RECONCILIATION_EXHAUSTED"] }, "stage": { "enum": ["REPORT"] } }, "required": ["reason", "completedAt"] } }], "properties": { "cancellationRequestedAt": { "$ref": "#/components/schemas/Timestamp" }, "completedAt": { "$ref": "#/components/schemas/Timestamp" }, "observedAt": { "$ref": "#/components/schemas/Timestamp" }, "reason": { "$ref": "#/components/schemas/PipelineRunReason" }, "resourceVersion": { "maximum": 9007199254740991, "minimum": 1, "type": "integer" }, "stage": { "$ref": "#/components/schemas/PipelineRunStage" }, "state": { "$ref": "#/components/schemas/PipelineRunState" } }, "required": ["observedAt", "resourceVersion", "stage", "state"], "type": "object" };
var schema58 = { "enum": ["EVENT_ADMITTED", "COMPLETED", "SOURCE_UNAVAILABLE", "COMMIT_MISMATCH", "EXECUTOR_UNAVAILABLE", "VERIFICATION_FAILED", "DEADLINE_EXCEEDED", "REPORT_UNAVAILABLE", "REPORT_CONFLICT", "CANCELLED", "EXTERNAL_EFFECT_UNCERTAIN", "RECONCILIATION_EXHAUSTED"], "type": "string" };
function validate175(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate175.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate175.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "EVENT_ADMITTED" || data === "COMPLETED" || data === "SOURCE_UNAVAILABLE" || data === "COMMIT_MISMATCH" || data === "EXECUTOR_UNAVAILABLE" || data === "VERIFICATION_FAILED" || data === "DEADLINE_EXCEEDED" || data === "REPORT_UNAVAILABLE" || data === "REPORT_CONFLICT" || data === "CANCELLED" || data === "EXTERNAL_EFFECT_UNCERTAIN" || data === "RECONCILIATION_EXHAUSTED")) {
    validate175.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema58.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate175.errors = vErrors;
  return errors === 0;
}
validate175.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema59 = { "enum": ["RECEIVE", "FETCH", "VERIFY", "REPORT"], "type": "string" };
function validate177(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate177.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate177.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "RECEIVE" || data === "FETCH" || data === "VERIFY" || data === "REPORT")) {
    validate177.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema59.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate177.errors = vErrors;
  return errors === 0;
}
validate177.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema60 = { "enum": ["QUEUED", "FETCHING", "VERIFYING", "REPORTING", "SUCCEEDED", "FAILED", "CANCELLED", "RECONCILING", "MANUAL_INTERVENTION"], "type": "string" };
function validate179(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate179.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate179.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "QUEUED" || data === "FETCHING" || data === "VERIFYING" || data === "REPORTING" || data === "SUCCEEDED" || data === "FAILED" || data === "CANCELLED" || data === "RECONCILING" || data === "MANUAL_INTERVENTION")) {
    validate179.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema60.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate179.errors = vErrors;
  return errors === 0;
}
validate179.evaluated = { "dynamicProps": false, "dynamicItems": false };
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
  const _errs1 = errors;
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.state === void 0 && (missing0 = "state")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.state !== void 0) {
        if ("QUEUED" !== data.state) {
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
    const _errs6 = errors;
    const _errs7 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing1;
      if (data.completedAt === void 0 && (missing1 = "completedAt")) {
        const err2 = {};
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    var valid3 = _errs7 === errors;
    if (valid3) {
      validate171.errors = [{ instancePath, schemaPath: "#/allOf/0/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
      return false;
    } else {
      errors = _errs6;
      if (vErrors !== null) {
        if (_errs6) {
          vErrors.length = _errs6;
        } else {
          vErrors = null;
        }
      }
    }
    if (errors === _errs5) {
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing2;
        if (data.reason === void 0 && (missing2 = "reason")) {
          validate171.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
          return false;
        } else {
          if (data.cancellationRequestedAt !== void 0) {
            var valid4 = false;
            validate171.errors = [{ instancePath: instancePath + "/cancellationRequestedAt", schemaPath: "#/allOf/0/then/properties/cancellationRequestedAt/false schema", keyword: "false schema", params: {}, message: "boolean schema is false" }];
            return false;
          } else {
            var valid4 = true;
          }
          if (valid4) {
            if (data.reason !== void 0) {
              const _errs8 = errors;
              if (!(data.reason === "EVENT_ADMITTED")) {
                validate171.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/0/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[0].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
              var valid4 = _errs8 === errors;
            } else {
              var valid4 = true;
            }
            if (valid4) {
              if (data.resourceVersion !== void 0) {
                const _errs9 = errors;
                if (1 !== data.resourceVersion) {
                  validate171.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/allOf/0/then/properties/resourceVersion/const", keyword: "const", params: { allowedValue: 1 }, message: "must be equal to constant" }];
                  return false;
                }
                var valid4 = _errs9 === errors;
              } else {
                var valid4 = true;
              }
              if (valid4) {
                if (data.stage !== void 0) {
                  const _errs10 = errors;
                  if (!(data.stage === "RECEIVE")) {
                    validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/0/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[0].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                    return false;
                  }
                  var valid4 = _errs10 === errors;
                } else {
                  var valid4 = true;
                }
              }
            }
          }
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.cancellationRequestedAt = true;
      props0.reason = true;
      props0.resourceVersion = true;
      props0.stage = true;
      props0.state = true;
    }
  }
  if (!valid1) {
    const err3 = { instancePath, schemaPath: "#/allOf/0/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
    if (vErrors === null) {
      vErrors = [err3];
    } else {
      vErrors.push(err3);
    }
    errors++;
    validate171.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs11 = errors;
    const _errs12 = errors;
    let valid5 = true;
    const _errs13 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing3;
      if (data.state === void 0 && (missing3 = "state")) {
        const err4 = {};
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      } else {
        if (data.state !== void 0) {
          if ("FETCHING" !== data.state) {
            const err5 = {};
            if (vErrors === null) {
              vErrors = [err5];
            } else {
              vErrors.push(err5);
            }
            errors++;
          }
        }
      }
    }
    var _valid1 = _errs13 === errors;
    errors = _errs12;
    if (vErrors !== null) {
      if (_errs12) {
        vErrors.length = _errs12;
      } else {
        vErrors = null;
      }
    }
    if (_valid1) {
      const _errs15 = errors;
      const _errs16 = errors;
      const _errs17 = errors;
      const _errs18 = errors;
      let valid8 = false;
      const _errs19 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing4;
        if (data.reason === void 0 && (missing4 = "reason")) {
          const err6 = {};
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        }
      }
      var _valid2 = _errs19 === errors;
      valid8 = valid8 || _valid2;
      const _errs20 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing5;
        if (data.completedAt === void 0 && (missing5 = "completedAt")) {
          const err7 = {};
          if (vErrors === null) {
            vErrors = [err7];
          } else {
            vErrors.push(err7);
          }
          errors++;
        }
      }
      var _valid2 = _errs20 === errors;
      valid8 = valid8 || _valid2;
      if (!valid8) {
        const err8 = {};
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      } else {
        errors = _errs18;
        if (vErrors !== null) {
          if (_errs18) {
            vErrors.length = _errs18;
          } else {
            vErrors = null;
          }
        }
      }
      var valid7 = _errs17 === errors;
      if (valid7) {
        validate171.errors = [{ instancePath, schemaPath: "#/allOf/1/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
        return false;
      } else {
        errors = _errs16;
        if (vErrors !== null) {
          if (_errs16) {
            vErrors.length = _errs16;
          } else {
            vErrors = null;
          }
        }
      }
      if (errors === _errs15) {
        if (data && typeof data == "object" && !Array.isArray(data)) {
          if (data.stage !== void 0) {
            if (!(data.stage === "FETCH")) {
              validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/1/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[1].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
              return false;
            }
          }
        }
      }
      var _valid1 = _errs15 === errors;
      valid5 = _valid1;
      if (valid5) {
        var props1 = {};
        props1.stage = true;
        props1.state = true;
      }
    }
    if (!valid5) {
      const err9 = { instancePath, schemaPath: "#/allOf/1/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
      if (vErrors === null) {
        vErrors = [err9];
      } else {
        vErrors.push(err9);
      }
      errors++;
      validate171.errors = vErrors;
      return false;
    }
    var valid0 = _errs11 === errors;
    if (valid0) {
      if (props0 !== true && props1 !== void 0) {
        if (props1 === true) {
          props0 = true;
        } else {
          props0 = props0 || {};
          Object.assign(props0, props1);
        }
      }
      const _errs22 = errors;
      const _errs23 = errors;
      let valid10 = true;
      const _errs24 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing6;
        if (data.state === void 0 && (missing6 = "state")) {
          const err10 = {};
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        } else {
          if (data.state !== void 0) {
            if ("VERIFYING" !== data.state) {
              const err11 = {};
              if (vErrors === null) {
                vErrors = [err11];
              } else {
                vErrors.push(err11);
              }
              errors++;
            }
          }
        }
      }
      var _valid3 = _errs24 === errors;
      errors = _errs23;
      if (vErrors !== null) {
        if (_errs23) {
          vErrors.length = _errs23;
        } else {
          vErrors = null;
        }
      }
      if (_valid3) {
        const _errs26 = errors;
        const _errs27 = errors;
        const _errs28 = errors;
        const _errs29 = errors;
        let valid13 = false;
        const _errs30 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing7;
          if (data.reason === void 0 && (missing7 = "reason")) {
            const err12 = {};
            if (vErrors === null) {
              vErrors = [err12];
            } else {
              vErrors.push(err12);
            }
            errors++;
          }
        }
        var _valid4 = _errs30 === errors;
        valid13 = valid13 || _valid4;
        const _errs31 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing8;
          if (data.completedAt === void 0 && (missing8 = "completedAt")) {
            const err13 = {};
            if (vErrors === null) {
              vErrors = [err13];
            } else {
              vErrors.push(err13);
            }
            errors++;
          }
        }
        var _valid4 = _errs31 === errors;
        valid13 = valid13 || _valid4;
        if (!valid13) {
          const err14 = {};
          if (vErrors === null) {
            vErrors = [err14];
          } else {
            vErrors.push(err14);
          }
          errors++;
        } else {
          errors = _errs29;
          if (vErrors !== null) {
            if (_errs29) {
              vErrors.length = _errs29;
            } else {
              vErrors = null;
            }
          }
        }
        var valid12 = _errs28 === errors;
        if (valid12) {
          validate171.errors = [{ instancePath, schemaPath: "#/allOf/2/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
          return false;
        } else {
          errors = _errs27;
          if (vErrors !== null) {
            if (_errs27) {
              vErrors.length = _errs27;
            } else {
              vErrors = null;
            }
          }
        }
        if (errors === _errs26) {
          if (data && typeof data == "object" && !Array.isArray(data)) {
            if (data.stage !== void 0) {
              if (!(data.stage === "VERIFY")) {
                validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/2/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[2].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
            }
          }
        }
        var _valid3 = _errs26 === errors;
        valid10 = _valid3;
        if (valid10) {
          var props2 = {};
          props2.stage = true;
          props2.state = true;
        }
      }
      if (!valid10) {
        const err15 = { instancePath, schemaPath: "#/allOf/2/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
        validate171.errors = vErrors;
        return false;
      }
      var valid0 = _errs22 === errors;
      if (valid0) {
        if (props0 !== true && props2 !== void 0) {
          if (props2 === true) {
            props0 = true;
          } else {
            props0 = props0 || {};
            Object.assign(props0, props2);
          }
        }
        const _errs33 = errors;
        const _errs34 = errors;
        let valid15 = true;
        const _errs35 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing9;
          if (data.state === void 0 && (missing9 = "state")) {
            const err16 = {};
            if (vErrors === null) {
              vErrors = [err16];
            } else {
              vErrors.push(err16);
            }
            errors++;
          } else {
            if (data.state !== void 0) {
              if ("REPORTING" !== data.state) {
                const err17 = {};
                if (vErrors === null) {
                  vErrors = [err17];
                } else {
                  vErrors.push(err17);
                }
                errors++;
              }
            }
          }
        }
        var _valid5 = _errs35 === errors;
        errors = _errs34;
        if (vErrors !== null) {
          if (_errs34) {
            vErrors.length = _errs34;
          } else {
            vErrors = null;
          }
        }
        if (_valid5) {
          const _errs37 = errors;
          const _errs38 = errors;
          const _errs39 = errors;
          const _errs40 = errors;
          let valid18 = false;
          const _errs41 = errors;
          if (data && typeof data == "object" && !Array.isArray(data)) {
            let missing10;
            if (data.reason === void 0 && (missing10 = "reason")) {
              const err18 = {};
              if (vErrors === null) {
                vErrors = [err18];
              } else {
                vErrors.push(err18);
              }
              errors++;
            }
          }
          var _valid6 = _errs41 === errors;
          valid18 = valid18 || _valid6;
          const _errs42 = errors;
          if (data && typeof data == "object" && !Array.isArray(data)) {
            let missing11;
            if (data.completedAt === void 0 && (missing11 = "completedAt")) {
              const err19 = {};
              if (vErrors === null) {
                vErrors = [err19];
              } else {
                vErrors.push(err19);
              }
              errors++;
            }
          }
          var _valid6 = _errs42 === errors;
          valid18 = valid18 || _valid6;
          if (!valid18) {
            const err20 = {};
            if (vErrors === null) {
              vErrors = [err20];
            } else {
              vErrors.push(err20);
            }
            errors++;
          } else {
            errors = _errs40;
            if (vErrors !== null) {
              if (_errs40) {
                vErrors.length = _errs40;
              } else {
                vErrors = null;
              }
            }
          }
          var valid17 = _errs39 === errors;
          if (valid17) {
            validate171.errors = [{ instancePath, schemaPath: "#/allOf/3/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
            return false;
          } else {
            errors = _errs38;
            if (vErrors !== null) {
              if (_errs38) {
                vErrors.length = _errs38;
              } else {
                vErrors = null;
              }
            }
          }
          if (errors === _errs37) {
            if (data && typeof data == "object" && !Array.isArray(data)) {
              if (data.stage !== void 0) {
                if (!(data.stage === "REPORT")) {
                  validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/3/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[3].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                  return false;
                }
              }
            }
          }
          var _valid5 = _errs37 === errors;
          valid15 = _valid5;
          if (valid15) {
            var props3 = {};
            props3.stage = true;
            props3.state = true;
          }
        }
        if (!valid15) {
          const err21 = { instancePath, schemaPath: "#/allOf/3/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
          if (vErrors === null) {
            vErrors = [err21];
          } else {
            vErrors.push(err21);
          }
          errors++;
          validate171.errors = vErrors;
          return false;
        }
        var valid0 = _errs33 === errors;
        if (valid0) {
          if (props0 !== true && props3 !== void 0) {
            if (props3 === true) {
              props0 = true;
            } else {
              props0 = props0 || {};
              Object.assign(props0, props3);
            }
          }
          const _errs44 = errors;
          const _errs45 = errors;
          let valid20 = true;
          const _errs46 = errors;
          if (data && typeof data == "object" && !Array.isArray(data)) {
            let missing12;
            if (data.state === void 0 && (missing12 = "state")) {
              const err22 = {};
              if (vErrors === null) {
                vErrors = [err22];
              } else {
                vErrors.push(err22);
              }
              errors++;
            } else {
              if (data.state !== void 0) {
                if ("SUCCEEDED" !== data.state) {
                  const err23 = {};
                  if (vErrors === null) {
                    vErrors = [err23];
                  } else {
                    vErrors.push(err23);
                  }
                  errors++;
                }
              }
            }
          }
          var _valid7 = _errs46 === errors;
          errors = _errs45;
          if (vErrors !== null) {
            if (_errs45) {
              vErrors.length = _errs45;
            } else {
              vErrors = null;
            }
          }
          if (_valid7) {
            const _errs48 = errors;
            if (data && typeof data == "object" && !Array.isArray(data)) {
              let missing13;
              if (data.reason === void 0 && (missing13 = "reason") || data.completedAt === void 0 && (missing13 = "completedAt")) {
                validate171.errors = [{ instancePath, schemaPath: "#/allOf/4/then/required", keyword: "required", params: { missingProperty: missing13 }, message: "must have required property '" + missing13 + "'" }];
                return false;
              } else {
                if (data.reason !== void 0) {
                  const _errs49 = errors;
                  if (!(data.reason === "COMPLETED")) {
                    validate171.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/4/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[4].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                    return false;
                  }
                  var valid22 = _errs49 === errors;
                } else {
                  var valid22 = true;
                }
                if (valid22) {
                  if (data.stage !== void 0) {
                    const _errs50 = errors;
                    if (!(data.stage === "REPORT")) {
                      validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/4/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[4].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                      return false;
                    }
                    var valid22 = _errs50 === errors;
                  } else {
                    var valid22 = true;
                  }
                }
              }
            }
            var _valid7 = _errs48 === errors;
            valid20 = _valid7;
            if (valid20) {
              var props4 = {};
              props4.reason = true;
              props4.stage = true;
              props4.state = true;
            }
          }
          if (!valid20) {
            const err24 = { instancePath, schemaPath: "#/allOf/4/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
            if (vErrors === null) {
              vErrors = [err24];
            } else {
              vErrors.push(err24);
            }
            errors++;
            validate171.errors = vErrors;
            return false;
          }
          var valid0 = _errs44 === errors;
          if (valid0) {
            if (props0 !== true && props4 !== void 0) {
              if (props4 === true) {
                props0 = true;
              } else {
                props0 = props0 || {};
                Object.assign(props0, props4);
              }
            }
            const _errs51 = errors;
            const _errs52 = errors;
            let valid23 = true;
            const _errs53 = errors;
            if (data && typeof data == "object" && !Array.isArray(data)) {
              let missing14;
              if (data.state === void 0 && (missing14 = "state")) {
                const err25 = {};
                if (vErrors === null) {
                  vErrors = [err25];
                } else {
                  vErrors.push(err25);
                }
                errors++;
              } else {
                if (data.state !== void 0) {
                  if ("FAILED" !== data.state) {
                    const err26 = {};
                    if (vErrors === null) {
                      vErrors = [err26];
                    } else {
                      vErrors.push(err26);
                    }
                    errors++;
                  }
                }
              }
            }
            var _valid8 = _errs53 === errors;
            errors = _errs52;
            if (vErrors !== null) {
              if (_errs52) {
                vErrors.length = _errs52;
              } else {
                vErrors = null;
              }
            }
            if (_valid8) {
              const _errs55 = errors;
              if (data && typeof data == "object" && !Array.isArray(data)) {
                let missing15;
                if (data.reason === void 0 && (missing15 = "reason") || data.completedAt === void 0 && (missing15 = "completedAt")) {
                  validate171.errors = [{ instancePath, schemaPath: "#/allOf/5/then/required", keyword: "required", params: { missingProperty: missing15 }, message: "must have required property '" + missing15 + "'" }];
                  return false;
                } else {
                  if (data.reason !== void 0) {
                    let data15 = data.reason;
                    const _errs56 = errors;
                    if (!(data15 === "SOURCE_UNAVAILABLE" || data15 === "COMMIT_MISMATCH" || data15 === "EXECUTOR_UNAVAILABLE" || data15 === "VERIFICATION_FAILED" || data15 === "DEADLINE_EXCEEDED" || data15 === "REPORT_UNAVAILABLE" || data15 === "REPORT_CONFLICT")) {
                      validate171.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/5/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[5].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                      return false;
                    }
                    var valid25 = _errs56 === errors;
                  } else {
                    var valid25 = true;
                  }
                  if (valid25) {
                    if (data.stage !== void 0) {
                      let data16 = data.stage;
                      const _errs57 = errors;
                      if (!(data16 === "RECEIVE" || data16 === "FETCH" || data16 === "VERIFY" || data16 === "REPORT")) {
                        validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/5/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[5].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                        return false;
                      }
                      var valid25 = _errs57 === errors;
                    } else {
                      var valid25 = true;
                    }
                  }
                }
              }
              var _valid8 = _errs55 === errors;
              valid23 = _valid8;
              if (valid23) {
                var props5 = {};
                props5.reason = true;
                props5.stage = true;
                props5.state = true;
              }
            }
            if (!valid23) {
              const err27 = { instancePath, schemaPath: "#/allOf/5/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
              if (vErrors === null) {
                vErrors = [err27];
              } else {
                vErrors.push(err27);
              }
              errors++;
              validate171.errors = vErrors;
              return false;
            }
            var valid0 = _errs51 === errors;
            if (valid0) {
              if (props0 !== true && props5 !== void 0) {
                if (props5 === true) {
                  props0 = true;
                } else {
                  props0 = props0 || {};
                  Object.assign(props0, props5);
                }
              }
              const _errs58 = errors;
              const _errs59 = errors;
              let valid26 = true;
              const _errs60 = errors;
              if (data && typeof data == "object" && !Array.isArray(data)) {
                let missing16;
                if (data.state === void 0 && (missing16 = "state")) {
                  const err28 = {};
                  if (vErrors === null) {
                    vErrors = [err28];
                  } else {
                    vErrors.push(err28);
                  }
                  errors++;
                } else {
                  if (data.state !== void 0) {
                    if ("CANCELLED" !== data.state) {
                      const err29 = {};
                      if (vErrors === null) {
                        vErrors = [err29];
                      } else {
                        vErrors.push(err29);
                      }
                      errors++;
                    }
                  }
                }
              }
              var _valid9 = _errs60 === errors;
              errors = _errs59;
              if (vErrors !== null) {
                if (_errs59) {
                  vErrors.length = _errs59;
                } else {
                  vErrors = null;
                }
              }
              if (_valid9) {
                const _errs62 = errors;
                if (data && typeof data == "object" && !Array.isArray(data)) {
                  let missing17;
                  if (data.reason === void 0 && (missing17 = "reason") || data.cancellationRequestedAt === void 0 && (missing17 = "cancellationRequestedAt") || data.completedAt === void 0 && (missing17 = "completedAt")) {
                    validate171.errors = [{ instancePath, schemaPath: "#/allOf/6/then/required", keyword: "required", params: { missingProperty: missing17 }, message: "must have required property '" + missing17 + "'" }];
                    return false;
                  } else {
                    if (data.reason !== void 0) {
                      const _errs63 = errors;
                      if (!(data.reason === "CANCELLED")) {
                        validate171.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/6/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[6].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                        return false;
                      }
                      var valid28 = _errs63 === errors;
                    } else {
                      var valid28 = true;
                    }
                    if (valid28) {
                      if (data.stage !== void 0) {
                        let data19 = data.stage;
                        const _errs64 = errors;
                        if (!(data19 === "RECEIVE" || data19 === "FETCH" || data19 === "VERIFY" || data19 === "REPORT")) {
                          validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/6/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[6].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                          return false;
                        }
                        var valid28 = _errs64 === errors;
                      } else {
                        var valid28 = true;
                      }
                    }
                  }
                }
                var _valid9 = _errs62 === errors;
                valid26 = _valid9;
                if (valid26) {
                  var props6 = {};
                  props6.reason = true;
                  props6.stage = true;
                  props6.state = true;
                }
              }
              if (!valid26) {
                const err30 = { instancePath, schemaPath: "#/allOf/6/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
                if (vErrors === null) {
                  vErrors = [err30];
                } else {
                  vErrors.push(err30);
                }
                errors++;
                validate171.errors = vErrors;
                return false;
              }
              var valid0 = _errs58 === errors;
              if (valid0) {
                if (props0 !== true && props6 !== void 0) {
                  if (props6 === true) {
                    props0 = true;
                  } else {
                    props0 = props0 || {};
                    Object.assign(props0, props6);
                  }
                }
                const _errs65 = errors;
                const _errs66 = errors;
                let valid29 = true;
                const _errs67 = errors;
                if (data && typeof data == "object" && !Array.isArray(data)) {
                  let missing18;
                  if (data.state === void 0 && (missing18 = "state")) {
                    const err31 = {};
                    if (vErrors === null) {
                      vErrors = [err31];
                    } else {
                      vErrors.push(err31);
                    }
                    errors++;
                  } else {
                    if (data.state !== void 0) {
                      if ("RECONCILING" !== data.state) {
                        const err32 = {};
                        if (vErrors === null) {
                          vErrors = [err32];
                        } else {
                          vErrors.push(err32);
                        }
                        errors++;
                      }
                    }
                  }
                }
                var _valid10 = _errs67 === errors;
                errors = _errs66;
                if (vErrors !== null) {
                  if (_errs66) {
                    vErrors.length = _errs66;
                  } else {
                    vErrors = null;
                  }
                }
                if (_valid10) {
                  const _errs69 = errors;
                  const _errs70 = errors;
                  const _errs71 = errors;
                  if (data && typeof data == "object" && !Array.isArray(data)) {
                    let missing19;
                    if (data.completedAt === void 0 && (missing19 = "completedAt")) {
                      const err33 = {};
                      if (vErrors === null) {
                        vErrors = [err33];
                      } else {
                        vErrors.push(err33);
                      }
                      errors++;
                    }
                  }
                  var valid31 = _errs71 === errors;
                  if (valid31) {
                    validate171.errors = [{ instancePath, schemaPath: "#/allOf/7/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
                    return false;
                  } else {
                    errors = _errs70;
                    if (vErrors !== null) {
                      if (_errs70) {
                        vErrors.length = _errs70;
                      } else {
                        vErrors = null;
                      }
                    }
                  }
                  if (errors === _errs69) {
                    if (data && typeof data == "object" && !Array.isArray(data)) {
                      let missing20;
                      if (data.reason === void 0 && (missing20 = "reason")) {
                        validate171.errors = [{ instancePath, schemaPath: "#/allOf/7/then/required", keyword: "required", params: { missingProperty: missing20 }, message: "must have required property '" + missing20 + "'" }];
                        return false;
                      } else {
                        if (data.reason !== void 0) {
                          const _errs72 = errors;
                          if (!(data.reason === "EXTERNAL_EFFECT_UNCERTAIN")) {
                            validate171.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/7/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[7].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                            return false;
                          }
                          var valid32 = _errs72 === errors;
                        } else {
                          var valid32 = true;
                        }
                        if (valid32) {
                          if (data.stage !== void 0) {
                            const _errs73 = errors;
                            if (!(data.stage === "REPORT")) {
                              validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/7/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[7].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                              return false;
                            }
                            var valid32 = _errs73 === errors;
                          } else {
                            var valid32 = true;
                          }
                        }
                      }
                    }
                  }
                  var _valid10 = _errs69 === errors;
                  valid29 = _valid10;
                  if (valid29) {
                    var props7 = {};
                    props7.reason = true;
                    props7.stage = true;
                    props7.state = true;
                  }
                }
                if (!valid29) {
                  const err34 = { instancePath, schemaPath: "#/allOf/7/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
                  if (vErrors === null) {
                    vErrors = [err34];
                  } else {
                    vErrors.push(err34);
                  }
                  errors++;
                  validate171.errors = vErrors;
                  return false;
                }
                var valid0 = _errs65 === errors;
                if (valid0) {
                  if (props0 !== true && props7 !== void 0) {
                    if (props7 === true) {
                      props0 = true;
                    } else {
                      props0 = props0 || {};
                      Object.assign(props0, props7);
                    }
                  }
                  const _errs74 = errors;
                  const _errs75 = errors;
                  let valid33 = true;
                  const _errs76 = errors;
                  if (data && typeof data == "object" && !Array.isArray(data)) {
                    let missing21;
                    if (data.state === void 0 && (missing21 = "state")) {
                      const err35 = {};
                      if (vErrors === null) {
                        vErrors = [err35];
                      } else {
                        vErrors.push(err35);
                      }
                      errors++;
                    } else {
                      if (data.state !== void 0) {
                        if ("MANUAL_INTERVENTION" !== data.state) {
                          const err36 = {};
                          if (vErrors === null) {
                            vErrors = [err36];
                          } else {
                            vErrors.push(err36);
                          }
                          errors++;
                        }
                      }
                    }
                  }
                  var _valid11 = _errs76 === errors;
                  errors = _errs75;
                  if (vErrors !== null) {
                    if (_errs75) {
                      vErrors.length = _errs75;
                    } else {
                      vErrors = null;
                    }
                  }
                  if (_valid11) {
                    const _errs78 = errors;
                    if (data && typeof data == "object" && !Array.isArray(data)) {
                      let missing22;
                      if (data.reason === void 0 && (missing22 = "reason") || data.completedAt === void 0 && (missing22 = "completedAt")) {
                        validate171.errors = [{ instancePath, schemaPath: "#/allOf/8/then/required", keyword: "required", params: { missingProperty: missing22 }, message: "must have required property '" + missing22 + "'" }];
                        return false;
                      } else {
                        if (data.reason !== void 0) {
                          const _errs79 = errors;
                          if (!(data.reason === "RECONCILIATION_EXHAUSTED")) {
                            validate171.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/8/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[8].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                            return false;
                          }
                          var valid35 = _errs79 === errors;
                        } else {
                          var valid35 = true;
                        }
                        if (valid35) {
                          if (data.stage !== void 0) {
                            const _errs80 = errors;
                            if (!(data.stage === "REPORT")) {
                              validate171.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/8/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[8].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                              return false;
                            }
                            var valid35 = _errs80 === errors;
                          } else {
                            var valid35 = true;
                          }
                        }
                      }
                    }
                    var _valid11 = _errs78 === errors;
                    valid33 = _valid11;
                    if (valid33) {
                      var props8 = {};
                      props8.reason = true;
                      props8.stage = true;
                      props8.state = true;
                    }
                  }
                  if (!valid33) {
                    const err37 = { instancePath, schemaPath: "#/allOf/8/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
                    if (vErrors === null) {
                      vErrors = [err37];
                    } else {
                      vErrors.push(err37);
                    }
                    errors++;
                    validate171.errors = vErrors;
                    return false;
                  }
                  var valid0 = _errs74 === errors;
                  if (valid0) {
                    if (props0 !== true && props8 !== void 0) {
                      if (props8 === true) {
                        props0 = true;
                      } else {
                        props0 = props0 || {};
                        Object.assign(props0, props8);
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing23;
      if (data.observedAt === void 0 && (missing23 = "observedAt") || data.resourceVersion === void 0 && (missing23 = "resourceVersion") || data.stage === void 0 && (missing23 = "stage") || data.state === void 0 && (missing23 = "state")) {
        validate171.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing23 }, message: "must have required property '" + missing23 + "'" }];
        return false;
      } else {
        const _errs81 = errors;
        for (const key0 in data) {
          if (!(key0 === "cancellationRequestedAt" || key0 === "completedAt" || key0 === "observedAt" || key0 === "reason" || key0 === "resourceVersion" || key0 === "stage" || key0 === "state")) {
            validate171.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs81 === errors) {
          if (data.cancellationRequestedAt !== void 0) {
            const _errs82 = errors;
            if (!validate91(data.cancellationRequestedAt, { instancePath: instancePath + "/cancellationRequestedAt", parentData: data, parentDataProperty: "cancellationRequestedAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
              errors = vErrors.length;
            }
            var valid36 = _errs82 === errors;
          } else {
            var valid36 = true;
          }
          if (valid36) {
            if (data.completedAt !== void 0) {
              const _errs83 = errors;
              if (!validate91(data.completedAt, { instancePath: instancePath + "/completedAt", parentData: data, parentDataProperty: "completedAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid36 = _errs83 === errors;
            } else {
              var valid36 = true;
            }
            if (valid36) {
              if (data.observedAt !== void 0) {
                const _errs84 = errors;
                if (!validate91(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                  errors = vErrors.length;
                }
                var valid36 = _errs84 === errors;
              } else {
                var valid36 = true;
              }
              if (valid36) {
                if (data.reason !== void 0) {
                  const _errs85 = errors;
                  if (!validate175(data.reason, { instancePath: instancePath + "/reason", parentData: data, parentDataProperty: "reason", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate175.errors : vErrors.concat(validate175.errors);
                    errors = vErrors.length;
                  }
                  var valid36 = _errs85 === errors;
                } else {
                  var valid36 = true;
                }
                if (valid36) {
                  if (data.resourceVersion !== void 0) {
                    let data30 = data.resourceVersion;
                    const _errs86 = errors;
                    if (!(typeof data30 == "number" && (!(data30 % 1) && !isNaN(data30)))) {
                      validate171.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                      return false;
                    }
                    if (errors === _errs86) {
                      if (typeof data30 == "number") {
                        if (data30 > 9007199254740991 || isNaN(data30)) {
                          validate171.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                          return false;
                        } else {
                          if (data30 < 1 || isNaN(data30)) {
                            validate171.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                            return false;
                          }
                        }
                      }
                    }
                    var valid36 = _errs86 === errors;
                  } else {
                    var valid36 = true;
                  }
                  if (valid36) {
                    if (data.stage !== void 0) {
                      const _errs88 = errors;
                      if (!validate177(data.stage, { instancePath: instancePath + "/stage", parentData: data, parentDataProperty: "stage", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate177.errors : vErrors.concat(validate177.errors);
                        errors = vErrors.length;
                      }
                      var valid36 = _errs88 === errors;
                    } else {
                      var valid36 = true;
                    }
                    if (valid36) {
                      if (data.state !== void 0) {
                        const _errs89 = errors;
                        if (!validate179(data.state, { instancePath: instancePath + "/state", parentData: data, parentDataProperty: "state", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate179.errors : vErrors.concat(validate179.errors);
                          errors = vErrors.length;
                        }
                        var valid36 = _errs89 === errors;
                      } else {
                        var valid36 = true;
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
      validate171.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate171.errors = vErrors;
  return errors === 0;
}
validate171.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate156(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate156.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.createdAt === void 0 && (missing0 = "createdAt") || data.id === void 0 && (missing0 = "id") || data.input === void 0 && (missing0 = "input") || data.inputDigest === void 0 && (missing0 = "inputDigest") || data.kind === void 0 && (missing0 = "kind") || data.pipelineId === void 0 && (missing0 = "pipelineId") || data.projectId === void 0 && (missing0 = "projectId") || data.scope === void 0 && (missing0 = "scope") || data.status === void 0 && (missing0 = "status") || data.updatedAt === void 0 && (missing0 = "updatedAt")) {
        validate156.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func21.call(schema54.properties, key0)) {
            validate156.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
              validate156.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.createdAt !== void 0) {
              const _errs3 = errors;
              if (!validate91(data.createdAt, { instancePath: instancePath + "/createdAt", parentData: data, parentDataProperty: "createdAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.id !== void 0) {
                const _errs4 = errors;
                if (!validate57(data.id, { instancePath: instancePath + "/id", parentData: data, parentDataProperty: "id", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.input !== void 0) {
                  const _errs5 = errors;
                  if (!validate159(data.input, { instancePath: instancePath + "/input", parentData: data, parentDataProperty: "input", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate159.errors : vErrors.concat(validate159.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.inputDigest !== void 0) {
                    let data4 = data.inputDigest;
                    const _errs6 = errors;
                    if (errors === _errs6) {
                      if (typeof data4 === "string") {
                        if (!pattern18.test(data4)) {
                          validate156.errors = [{ instancePath: instancePath + "/inputDigest", schemaPath: "#/properties/inputDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                          return false;
                        }
                      } else {
                        validate156.errors = [{ instancePath: instancePath + "/inputDigest", schemaPath: "#/properties/inputDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                        return false;
                      }
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.kind !== void 0) {
                      const _errs8 = errors;
                      if ("PipelineRun" !== data.kind) {
                        validate156.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "PipelineRun" }, message: "must be equal to constant" }];
                        return false;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.pipelineId !== void 0) {
                        const _errs9 = errors;
                        if (!validate57(data.pipelineId, { instancePath: instancePath + "/pipelineId", parentData: data, parentDataProperty: "pipelineId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs9 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.projectId !== void 0) {
                          const _errs10 = errors;
                          if (!validate57(data.projectId, { instancePath: instancePath + "/projectId", parentData: data, parentDataProperty: "projectId", rootData, dynamicAnchors })) {
                            vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                            errors = vErrors.length;
                          }
                          var valid0 = _errs10 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.replay !== void 0) {
                            const _errs11 = errors;
                            if (!validate167(data.replay, { instancePath: instancePath + "/replay", parentData: data, parentDataProperty: "replay", rootData, dynamicAnchors })) {
                              vErrors = vErrors === null ? validate167.errors : vErrors.concat(validate167.errors);
                              errors = vErrors.length;
                            }
                            var valid0 = _errs11 === errors;
                          } else {
                            var valid0 = true;
                          }
                          if (valid0) {
                            if (data.scope !== void 0) {
                              const _errs12 = errors;
                              if (!validate94(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                                vErrors = vErrors === null ? validate94.errors : vErrors.concat(validate94.errors);
                                errors = vErrors.length;
                              }
                              var valid0 = _errs12 === errors;
                            } else {
                              var valid0 = true;
                            }
                            if (valid0) {
                              if (data.status !== void 0) {
                                const _errs13 = errors;
                                if (!validate171(data.status, { instancePath: instancePath + "/status", parentData: data, parentDataProperty: "status", rootData, dynamicAnchors })) {
                                  vErrors = vErrors === null ? validate171.errors : vErrors.concat(validate171.errors);
                                  errors = vErrors.length;
                                }
                                var valid0 = _errs13 === errors;
                              } else {
                                var valid0 = true;
                              }
                              if (valid0) {
                                if (data.updatedAt !== void 0) {
                                  const _errs14 = errors;
                                  if (!validate91(data.updatedAt, { instancePath: instancePath + "/updatedAt", parentData: data, parentDataProperty: "updatedAt", rootData, dynamicAnchors })) {
                                    vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                                    errors = vErrors.length;
                                  }
                                  var valid0 = _errs14 === errors;
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
    } else {
      validate156.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate156.errors = vErrors;
  return errors === 0;
}
validate156.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRunInput = validate183;
function validate183(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate183.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.change === void 0 && (missing0 = "change") || data.pipelineRevisionDigest === void 0 && (missing0 = "pipelineRevisionDigest") || data.pipelineRevisionId === void 0 && (missing0 = "pipelineRevisionId") || data.repositoryBindingDigest === void 0 && (missing0 = "repositoryBindingDigest") || data.repositoryBindingId === void 0 && (missing0 = "repositoryBindingId") || data.sourceEventDigest === void 0 && (missing0 = "sourceEventDigest") || data.sourceEventId === void 0 && (missing0 = "sourceEventId")) {
        validate183.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "change" || key0 === "pipelineRevisionDigest" || key0 === "pipelineRevisionId" || key0 === "repositoryBindingDigest" || key0 === "repositoryBindingId" || key0 === "sourceEventDigest" || key0 === "sourceEventId")) {
            validate183.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.change !== void 0) {
            const _errs2 = errors;
            if (!validate54(data.change, { instancePath: instancePath + "/change", parentData: data, parentDataProperty: "change", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate54.errors : vErrors.concat(validate54.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.pipelineRevisionDigest !== void 0) {
              let data1 = data.pipelineRevisionDigest;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (!pattern18.test(data1)) {
                    validate183.errors = [{ instancePath: instancePath + "/pipelineRevisionDigest", schemaPath: "#/properties/pipelineRevisionDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                    return false;
                  }
                } else {
                  validate183.errors = [{ instancePath: instancePath + "/pipelineRevisionDigest", schemaPath: "#/properties/pipelineRevisionDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.pipelineRevisionId !== void 0) {
                const _errs5 = errors;
                if (!validate57(data.pipelineRevisionId, { instancePath: instancePath + "/pipelineRevisionId", parentData: data, parentDataProperty: "pipelineRevisionId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.repositoryBindingDigest !== void 0) {
                  let data3 = data.repositoryBindingDigest;
                  const _errs6 = errors;
                  if (errors === _errs6) {
                    if (typeof data3 === "string") {
                      if (!pattern18.test(data3)) {
                        validate183.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                        return false;
                      }
                    } else {
                      validate183.errors = [{ instancePath: instancePath + "/repositoryBindingDigest", schemaPath: "#/properties/repositoryBindingDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                      return false;
                    }
                  }
                  var valid0 = _errs6 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.repositoryBindingId !== void 0) {
                    const _errs8 = errors;
                    if (!validate57(data.repositoryBindingId, { instancePath: instancePath + "/repositoryBindingId", parentData: data, parentDataProperty: "repositoryBindingId", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs8 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.sourceEventDigest !== void 0) {
                      let data5 = data.sourceEventDigest;
                      const _errs9 = errors;
                      if (errors === _errs9) {
                        if (typeof data5 === "string") {
                          if (!pattern18.test(data5)) {
                            validate183.errors = [{ instancePath: instancePath + "/sourceEventDigest", schemaPath: "#/properties/sourceEventDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                            return false;
                          }
                        } else {
                          validate183.errors = [{ instancePath: instancePath + "/sourceEventDigest", schemaPath: "#/properties/sourceEventDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                          return false;
                        }
                      }
                      var valid0 = _errs9 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.sourceEventId !== void 0) {
                        const _errs11 = errors;
                        if (!validate57(data.sourceEventId, { instancePath: instancePath + "/sourceEventId", parentData: data, parentDataProperty: "sourceEventId", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
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
    } else {
      validate183.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate183.errors = vErrors;
  return errors === 0;
}
validate183.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRunLogChunk = validate188;
var schema64 = { "enum": ["GO_TEST", "GO_VET"], "type": "string" };
function validate191(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate191.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate191.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "GO_TEST" || data === "GO_VET")) {
    validate191.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema64.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate191.errors = vErrors;
  return errors === 0;
}
validate191.evaluated = { "dynamicProps": false, "dynamicItems": false };
function validate190(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate190.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind") || data.ordinal === void 0 && (missing0 = "ordinal")) {
        validate190.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "kind" || key0 === "ordinal")) {
            validate190.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.kind !== void 0) {
            const _errs2 = errors;
            if (!validate191(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate191.errors : vErrors.concat(validate191.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.ordinal !== void 0) {
              let data1 = data.ordinal;
              const _errs3 = errors;
              if (!(typeof data1 == "number" && (!(data1 % 1) && !isNaN(data1)))) {
                validate190.errors = [{ instancePath: instancePath + "/ordinal", schemaPath: "#/properties/ordinal/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                return false;
              }
              if (errors === _errs3) {
                if (typeof data1 == "number") {
                  if (data1 > 2 || isNaN(data1)) {
                    validate190.errors = [{ instancePath: instancePath + "/ordinal", schemaPath: "#/properties/ordinal/maximum", keyword: "maximum", params: { comparison: "<=", limit: 2 }, message: "must be <= 2" }];
                    return false;
                  } else {
                    if (data1 < 1 || isNaN(data1)) {
                      validate190.errors = [{ instancePath: instancePath + "/ordinal", schemaPath: "#/properties/ordinal/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                      return false;
                    }
                  }
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate190.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate190.errors = vErrors;
  return errors === 0;
}
validate190.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate188(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate188.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.content === void 0 && (missing0 = "content") || data.expiresAt === void 0 && (missing0 = "expiresAt") || data.sequence === void 0 && (missing0 = "sequence") || data.step === void 0 && (missing0 = "step")) {
        validate188.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "content" || key0 === "expiresAt" || key0 === "sequence" || key0 === "step")) {
            validate188.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.content !== void 0) {
            let data0 = data.content;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (typeof data0 === "string") {
                if (func1(data0) > 65536) {
                  validate188.errors = [{ instancePath: instancePath + "/content", schemaPath: "#/properties/content/maxLength", keyword: "maxLength", params: { limit: 65536 }, message: "must NOT have more than 65536 characters" }];
                  return false;
                } else {
                  if (func1(data0) < 1) {
                    validate188.errors = [{ instancePath: instancePath + "/content", schemaPath: "#/properties/content/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                    return false;
                  }
                }
              } else {
                validate188.errors = [{ instancePath: instancePath + "/content", schemaPath: "#/properties/content/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.expiresAt !== void 0) {
              const _errs4 = errors;
              if (!validate91(data.expiresAt, { instancePath: instancePath + "/expiresAt", parentData: data, parentDataProperty: "expiresAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.sequence !== void 0) {
                let data2 = data.sequence;
                const _errs5 = errors;
                if (!(typeof data2 == "number" && (!(data2 % 1) && !isNaN(data2)))) {
                  validate188.errors = [{ instancePath: instancePath + "/sequence", schemaPath: "#/properties/sequence/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                  return false;
                }
                if (errors === _errs5) {
                  if (typeof data2 == "number") {
                    if (data2 > 8388608 || isNaN(data2)) {
                      validate188.errors = [{ instancePath: instancePath + "/sequence", schemaPath: "#/properties/sequence/maximum", keyword: "maximum", params: { comparison: "<=", limit: 8388608 }, message: "must be <= 8388608" }];
                      return false;
                    } else {
                      if (data2 < 1 || isNaN(data2)) {
                        validate188.errors = [{ instancePath: instancePath + "/sequence", schemaPath: "#/properties/sequence/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
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
                if (data.step !== void 0) {
                  const _errs7 = errors;
                  if (!validate190(data.step, { instancePath: instancePath + "/step", parentData: data, parentDataProperty: "step", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate190.errors : vErrors.concat(validate190.errors);
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
      validate188.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate188.errors = vErrors;
  return errors === 0;
}
validate188.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRunLogPage = validate194;
var schema65 = { "additionalProperties": false, "properties": { "afterSequence": { "maximum": 8388608, "minimum": 0, "type": "integer" }, "apiVersion": { "const": "devops.matrix.xiak.com/v1" }, "chunks": { "items": { "$ref": "#/components/schemas/PipelineRunLogChunk" }, "maxItems": 4, "type": "array" }, "hasMore": { "type": "boolean" }, "kind": { "const": "PipelineRunLogPage" }, "nextSequence": { "maximum": 8388608, "minimum": 0, "type": "integer" }, "readAt": { "$ref": "#/components/schemas/Timestamp" }, "runId": { "$ref": "#/components/schemas/ResourceID" }, "truncated": { "type": "boolean" } }, "required": ["afterSequence", "apiVersion", "chunks", "hasMore", "kind", "nextSequence", "readAt", "runId", "truncated"], "type": "object" };
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
      if (data.afterSequence === void 0 && (missing0 = "afterSequence") || data.apiVersion === void 0 && (missing0 = "apiVersion") || data.chunks === void 0 && (missing0 = "chunks") || data.hasMore === void 0 && (missing0 = "hasMore") || data.kind === void 0 && (missing0 = "kind") || data.nextSequence === void 0 && (missing0 = "nextSequence") || data.readAt === void 0 && (missing0 = "readAt") || data.runId === void 0 && (missing0 = "runId") || data.truncated === void 0 && (missing0 = "truncated")) {
        validate194.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!func21.call(schema65.properties, key0)) {
            validate194.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.afterSequence !== void 0) {
            let data0 = data.afterSequence;
            const _errs2 = errors;
            if (!(typeof data0 == "number" && (!(data0 % 1) && !isNaN(data0)))) {
              validate194.errors = [{ instancePath: instancePath + "/afterSequence", schemaPath: "#/properties/afterSequence/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
              return false;
            }
            if (errors === _errs2) {
              if (typeof data0 == "number") {
                if (data0 > 8388608 || isNaN(data0)) {
                  validate194.errors = [{ instancePath: instancePath + "/afterSequence", schemaPath: "#/properties/afterSequence/maximum", keyword: "maximum", params: { comparison: "<=", limit: 8388608 }, message: "must be <= 8388608" }];
                  return false;
                } else {
                  if (data0 < 0 || isNaN(data0)) {
                    validate194.errors = [{ instancePath: instancePath + "/afterSequence", schemaPath: "#/properties/afterSequence/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
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
            if (data.apiVersion !== void 0) {
              const _errs4 = errors;
              if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
                validate194.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.chunks !== void 0) {
                let data2 = data.chunks;
                const _errs5 = errors;
                if (errors === _errs5) {
                  if (Array.isArray(data2)) {
                    if (data2.length > 4) {
                      validate194.errors = [{ instancePath: instancePath + "/chunks", schemaPath: "#/properties/chunks/maxItems", keyword: "maxItems", params: { limit: 4 }, message: "must NOT have more than 4 items" }];
                      return false;
                    } else {
                      var valid1 = true;
                      const len0 = data2.length;
                      for (let i0 = 0; i0 < len0; i0++) {
                        const _errs7 = errors;
                        if (!validate188(data2[i0], { instancePath: instancePath + "/chunks/" + i0, parentData: data2, parentDataProperty: i0, rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate188.errors : vErrors.concat(validate188.errors);
                          errors = vErrors.length;
                        }
                        var valid1 = _errs7 === errors;
                        if (!valid1) {
                          break;
                        }
                      }
                    }
                  } else {
                    validate194.errors = [{ instancePath: instancePath + "/chunks", schemaPath: "#/properties/chunks/type", keyword: "type", params: { type: "array" }, message: "must be array" }];
                    return false;
                  }
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.hasMore !== void 0) {
                  const _errs8 = errors;
                  if (typeof data.hasMore !== "boolean") {
                    validate194.errors = [{ instancePath: instancePath + "/hasMore", schemaPath: "#/properties/hasMore/type", keyword: "type", params: { type: "boolean" }, message: "must be boolean" }];
                    return false;
                  }
                  var valid0 = _errs8 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.kind !== void 0) {
                    const _errs10 = errors;
                    if ("PipelineRunLogPage" !== data.kind) {
                      validate194.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "PipelineRunLogPage" }, message: "must be equal to constant" }];
                      return false;
                    }
                    var valid0 = _errs10 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.nextSequence !== void 0) {
                      let data6 = data.nextSequence;
                      const _errs11 = errors;
                      if (!(typeof data6 == "number" && (!(data6 % 1) && !isNaN(data6)))) {
                        validate194.errors = [{ instancePath: instancePath + "/nextSequence", schemaPath: "#/properties/nextSequence/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                        return false;
                      }
                      if (errors === _errs11) {
                        if (typeof data6 == "number") {
                          if (data6 > 8388608 || isNaN(data6)) {
                            validate194.errors = [{ instancePath: instancePath + "/nextSequence", schemaPath: "#/properties/nextSequence/maximum", keyword: "maximum", params: { comparison: "<=", limit: 8388608 }, message: "must be <= 8388608" }];
                            return false;
                          } else {
                            if (data6 < 0 || isNaN(data6)) {
                              validate194.errors = [{ instancePath: instancePath + "/nextSequence", schemaPath: "#/properties/nextSequence/minimum", keyword: "minimum", params: { comparison: ">=", limit: 0 }, message: "must be >= 0" }];
                              return false;
                            }
                          }
                        }
                      }
                      var valid0 = _errs11 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.readAt !== void 0) {
                        const _errs13 = errors;
                        if (!validate91(data.readAt, { instancePath: instancePath + "/readAt", parentData: data, parentDataProperty: "readAt", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                          errors = vErrors.length;
                        }
                        var valid0 = _errs13 === errors;
                      } else {
                        var valid0 = true;
                      }
                      if (valid0) {
                        if (data.runId !== void 0) {
                          const _errs14 = errors;
                          if (!validate57(data.runId, { instancePath: instancePath + "/runId", parentData: data, parentDataProperty: "runId", rootData, dynamicAnchors })) {
                            vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                            errors = vErrors.length;
                          }
                          var valid0 = _errs14 === errors;
                        } else {
                          var valid0 = true;
                        }
                        if (valid0) {
                          if (data.truncated !== void 0) {
                            const _errs15 = errors;
                            if (typeof data.truncated !== "boolean") {
                              validate194.errors = [{ instancePath: instancePath + "/truncated", schemaPath: "#/properties/truncated/type", keyword: "type", params: { type: "boolean" }, message: "must be boolean" }];
                              return false;
                            }
                            var valid0 = _errs15 === errors;
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
      validate194.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate194.errors = vErrors;
  return errors === 0;
}
validate194.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRunReason = validate198;
function validate198(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate198.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate198.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "EVENT_ADMITTED" || data === "COMPLETED" || data === "SOURCE_UNAVAILABLE" || data === "COMMIT_MISMATCH" || data === "EXECUTOR_UNAVAILABLE" || data === "VERIFICATION_FAILED" || data === "DEADLINE_EXCEEDED" || data === "REPORT_UNAVAILABLE" || data === "REPORT_CONFLICT" || data === "CANCELLED" || data === "EXTERNAL_EFFECT_UNCERTAIN" || data === "RECONCILIATION_EXHAUSTED")) {
    validate198.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema58.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate198.errors = vErrors;
  return errors === 0;
}
validate198.evaluated = { "dynamicProps": false, "dynamicItems": false };
var PipelineRunReplay = validate199;
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
      if (data.commandId === void 0 && (missing0 = "commandId") || data.requestedBy === void 0 && (missing0 = "requestedBy") || data.sourceRunId === void 0 && (missing0 = "sourceRunId")) {
        validate199.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "commandId" || key0 === "requestedBy" || key0 === "sourceRunId")) {
            validate199.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.commandId !== void 0) {
            let data0 = data.commandId;
            const _errs2 = errors;
            if (errors === _errs2) {
              if (typeof data0 === "string") {
                if (!pattern30.test(data0)) {
                  validate199.errors = [{ instancePath: instancePath + "/commandId", schemaPath: "#/properties/commandId/pattern", keyword: "pattern", params: { pattern: "^operation-[0-9a-f]{64}$" }, message: 'must match pattern "^operation-[0-9a-f]{64}$"' }];
                  return false;
                }
              } else {
                validate199.errors = [{ instancePath: instancePath + "/commandId", schemaPath: "#/properties/commandId/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                return false;
              }
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.requestedBy !== void 0) {
              const _errs4 = errors;
              if (!validate113(data.requestedBy, { instancePath: instancePath + "/requestedBy", parentData: data, parentDataProperty: "requestedBy", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate113.errors : vErrors.concat(validate113.errors);
                errors = vErrors.length;
              }
              var valid0 = _errs4 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.sourceRunId !== void 0) {
                let data2 = data.sourceRunId;
                const _errs5 = errors;
                if (errors === _errs5) {
                  if (typeof data2 === "string") {
                    if (!pattern31.test(data2)) {
                      validate199.errors = [{ instancePath: instancePath + "/sourceRunId", schemaPath: "#/properties/sourceRunId/pattern", keyword: "pattern", params: { pattern: "^pipeline-run-[0-9a-f]{48}$" }, message: 'must match pattern "^pipeline-run-[0-9a-f]{48}$"' }];
                      return false;
                    }
                  } else {
                    validate199.errors = [{ instancePath: instancePath + "/sourceRunId", schemaPath: "#/properties/sourceRunId/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
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
      validate199.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate199.errors = vErrors;
  return errors === 0;
}
validate199.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var PipelineRunStage = validate201;
function validate201(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate201.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate201.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "RECEIVE" || data === "FETCH" || data === "VERIFY" || data === "REPORT")) {
    validate201.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema59.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate201.errors = vErrors;
  return errors === 0;
}
validate201.evaluated = { "dynamicProps": false, "dynamicItems": false };
var PipelineRunState = validate202;
function validate202(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate202.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate202.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "QUEUED" || data === "FETCHING" || data === "VERIFYING" || data === "REPORTING" || data === "SUCCEEDED" || data === "FAILED" || data === "CANCELLED" || data === "RECONCILING" || data === "MANUAL_INTERVENTION")) {
    validate202.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema60.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate202.errors = vErrors;
  return errors === 0;
}
validate202.evaluated = { "dynamicProps": false, "dynamicItems": false };
var PipelineRunStatus = validate203;
function validate203(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate203.evaluated;
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
    if (data.state === void 0 && (missing0 = "state")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.state !== void 0) {
        if ("QUEUED" !== data.state) {
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
    const _errs6 = errors;
    const _errs7 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing1;
      if (data.completedAt === void 0 && (missing1 = "completedAt")) {
        const err2 = {};
        if (vErrors === null) {
          vErrors = [err2];
        } else {
          vErrors.push(err2);
        }
        errors++;
      }
    }
    var valid3 = _errs7 === errors;
    if (valid3) {
      validate203.errors = [{ instancePath, schemaPath: "#/allOf/0/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
      return false;
    } else {
      errors = _errs6;
      if (vErrors !== null) {
        if (_errs6) {
          vErrors.length = _errs6;
        } else {
          vErrors = null;
        }
      }
    }
    if (errors === _errs5) {
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing2;
        if (data.reason === void 0 && (missing2 = "reason")) {
          validate203.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing2 }, message: "must have required property '" + missing2 + "'" }];
          return false;
        } else {
          if (data.cancellationRequestedAt !== void 0) {
            var valid4 = false;
            validate203.errors = [{ instancePath: instancePath + "/cancellationRequestedAt", schemaPath: "#/allOf/0/then/properties/cancellationRequestedAt/false schema", keyword: "false schema", params: {}, message: "boolean schema is false" }];
            return false;
          } else {
            var valid4 = true;
          }
          if (valid4) {
            if (data.reason !== void 0) {
              const _errs8 = errors;
              if (!(data.reason === "EVENT_ADMITTED")) {
                validate203.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/0/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[0].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
              var valid4 = _errs8 === errors;
            } else {
              var valid4 = true;
            }
            if (valid4) {
              if (data.resourceVersion !== void 0) {
                const _errs9 = errors;
                if (1 !== data.resourceVersion) {
                  validate203.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/allOf/0/then/properties/resourceVersion/const", keyword: "const", params: { allowedValue: 1 }, message: "must be equal to constant" }];
                  return false;
                }
                var valid4 = _errs9 === errors;
              } else {
                var valid4 = true;
              }
              if (valid4) {
                if (data.stage !== void 0) {
                  const _errs10 = errors;
                  if (!(data.stage === "RECEIVE")) {
                    validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/0/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[0].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                    return false;
                  }
                  var valid4 = _errs10 === errors;
                } else {
                  var valid4 = true;
                }
              }
            }
          }
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.cancellationRequestedAt = true;
      props0.reason = true;
      props0.resourceVersion = true;
      props0.stage = true;
      props0.state = true;
    }
  }
  if (!valid1) {
    const err3 = { instancePath, schemaPath: "#/allOf/0/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
    if (vErrors === null) {
      vErrors = [err3];
    } else {
      vErrors.push(err3);
    }
    errors++;
    validate203.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs11 = errors;
    const _errs12 = errors;
    let valid5 = true;
    const _errs13 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing3;
      if (data.state === void 0 && (missing3 = "state")) {
        const err4 = {};
        if (vErrors === null) {
          vErrors = [err4];
        } else {
          vErrors.push(err4);
        }
        errors++;
      } else {
        if (data.state !== void 0) {
          if ("FETCHING" !== data.state) {
            const err5 = {};
            if (vErrors === null) {
              vErrors = [err5];
            } else {
              vErrors.push(err5);
            }
            errors++;
          }
        }
      }
    }
    var _valid1 = _errs13 === errors;
    errors = _errs12;
    if (vErrors !== null) {
      if (_errs12) {
        vErrors.length = _errs12;
      } else {
        vErrors = null;
      }
    }
    if (_valid1) {
      const _errs15 = errors;
      const _errs16 = errors;
      const _errs17 = errors;
      const _errs18 = errors;
      let valid8 = false;
      const _errs19 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing4;
        if (data.reason === void 0 && (missing4 = "reason")) {
          const err6 = {};
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        }
      }
      var _valid2 = _errs19 === errors;
      valid8 = valid8 || _valid2;
      const _errs20 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing5;
        if (data.completedAt === void 0 && (missing5 = "completedAt")) {
          const err7 = {};
          if (vErrors === null) {
            vErrors = [err7];
          } else {
            vErrors.push(err7);
          }
          errors++;
        }
      }
      var _valid2 = _errs20 === errors;
      valid8 = valid8 || _valid2;
      if (!valid8) {
        const err8 = {};
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
      } else {
        errors = _errs18;
        if (vErrors !== null) {
          if (_errs18) {
            vErrors.length = _errs18;
          } else {
            vErrors = null;
          }
        }
      }
      var valid7 = _errs17 === errors;
      if (valid7) {
        validate203.errors = [{ instancePath, schemaPath: "#/allOf/1/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
        return false;
      } else {
        errors = _errs16;
        if (vErrors !== null) {
          if (_errs16) {
            vErrors.length = _errs16;
          } else {
            vErrors = null;
          }
        }
      }
      if (errors === _errs15) {
        if (data && typeof data == "object" && !Array.isArray(data)) {
          if (data.stage !== void 0) {
            if (!(data.stage === "FETCH")) {
              validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/1/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[1].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
              return false;
            }
          }
        }
      }
      var _valid1 = _errs15 === errors;
      valid5 = _valid1;
      if (valid5) {
        var props1 = {};
        props1.stage = true;
        props1.state = true;
      }
    }
    if (!valid5) {
      const err9 = { instancePath, schemaPath: "#/allOf/1/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
      if (vErrors === null) {
        vErrors = [err9];
      } else {
        vErrors.push(err9);
      }
      errors++;
      validate203.errors = vErrors;
      return false;
    }
    var valid0 = _errs11 === errors;
    if (valid0) {
      if (props0 !== true && props1 !== void 0) {
        if (props1 === true) {
          props0 = true;
        } else {
          props0 = props0 || {};
          Object.assign(props0, props1);
        }
      }
      const _errs22 = errors;
      const _errs23 = errors;
      let valid10 = true;
      const _errs24 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing6;
        if (data.state === void 0 && (missing6 = "state")) {
          const err10 = {};
          if (vErrors === null) {
            vErrors = [err10];
          } else {
            vErrors.push(err10);
          }
          errors++;
        } else {
          if (data.state !== void 0) {
            if ("VERIFYING" !== data.state) {
              const err11 = {};
              if (vErrors === null) {
                vErrors = [err11];
              } else {
                vErrors.push(err11);
              }
              errors++;
            }
          }
        }
      }
      var _valid3 = _errs24 === errors;
      errors = _errs23;
      if (vErrors !== null) {
        if (_errs23) {
          vErrors.length = _errs23;
        } else {
          vErrors = null;
        }
      }
      if (_valid3) {
        const _errs26 = errors;
        const _errs27 = errors;
        const _errs28 = errors;
        const _errs29 = errors;
        let valid13 = false;
        const _errs30 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing7;
          if (data.reason === void 0 && (missing7 = "reason")) {
            const err12 = {};
            if (vErrors === null) {
              vErrors = [err12];
            } else {
              vErrors.push(err12);
            }
            errors++;
          }
        }
        var _valid4 = _errs30 === errors;
        valid13 = valid13 || _valid4;
        const _errs31 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing8;
          if (data.completedAt === void 0 && (missing8 = "completedAt")) {
            const err13 = {};
            if (vErrors === null) {
              vErrors = [err13];
            } else {
              vErrors.push(err13);
            }
            errors++;
          }
        }
        var _valid4 = _errs31 === errors;
        valid13 = valid13 || _valid4;
        if (!valid13) {
          const err14 = {};
          if (vErrors === null) {
            vErrors = [err14];
          } else {
            vErrors.push(err14);
          }
          errors++;
        } else {
          errors = _errs29;
          if (vErrors !== null) {
            if (_errs29) {
              vErrors.length = _errs29;
            } else {
              vErrors = null;
            }
          }
        }
        var valid12 = _errs28 === errors;
        if (valid12) {
          validate203.errors = [{ instancePath, schemaPath: "#/allOf/2/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
          return false;
        } else {
          errors = _errs27;
          if (vErrors !== null) {
            if (_errs27) {
              vErrors.length = _errs27;
            } else {
              vErrors = null;
            }
          }
        }
        if (errors === _errs26) {
          if (data && typeof data == "object" && !Array.isArray(data)) {
            if (data.stage !== void 0) {
              if (!(data.stage === "VERIFY")) {
                validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/2/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[2].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
            }
          }
        }
        var _valid3 = _errs26 === errors;
        valid10 = _valid3;
        if (valid10) {
          var props2 = {};
          props2.stage = true;
          props2.state = true;
        }
      }
      if (!valid10) {
        const err15 = { instancePath, schemaPath: "#/allOf/2/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
        if (vErrors === null) {
          vErrors = [err15];
        } else {
          vErrors.push(err15);
        }
        errors++;
        validate203.errors = vErrors;
        return false;
      }
      var valid0 = _errs22 === errors;
      if (valid0) {
        if (props0 !== true && props2 !== void 0) {
          if (props2 === true) {
            props0 = true;
          } else {
            props0 = props0 || {};
            Object.assign(props0, props2);
          }
        }
        const _errs33 = errors;
        const _errs34 = errors;
        let valid15 = true;
        const _errs35 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing9;
          if (data.state === void 0 && (missing9 = "state")) {
            const err16 = {};
            if (vErrors === null) {
              vErrors = [err16];
            } else {
              vErrors.push(err16);
            }
            errors++;
          } else {
            if (data.state !== void 0) {
              if ("REPORTING" !== data.state) {
                const err17 = {};
                if (vErrors === null) {
                  vErrors = [err17];
                } else {
                  vErrors.push(err17);
                }
                errors++;
              }
            }
          }
        }
        var _valid5 = _errs35 === errors;
        errors = _errs34;
        if (vErrors !== null) {
          if (_errs34) {
            vErrors.length = _errs34;
          } else {
            vErrors = null;
          }
        }
        if (_valid5) {
          const _errs37 = errors;
          const _errs38 = errors;
          const _errs39 = errors;
          const _errs40 = errors;
          let valid18 = false;
          const _errs41 = errors;
          if (data && typeof data == "object" && !Array.isArray(data)) {
            let missing10;
            if (data.reason === void 0 && (missing10 = "reason")) {
              const err18 = {};
              if (vErrors === null) {
                vErrors = [err18];
              } else {
                vErrors.push(err18);
              }
              errors++;
            }
          }
          var _valid6 = _errs41 === errors;
          valid18 = valid18 || _valid6;
          const _errs42 = errors;
          if (data && typeof data == "object" && !Array.isArray(data)) {
            let missing11;
            if (data.completedAt === void 0 && (missing11 = "completedAt")) {
              const err19 = {};
              if (vErrors === null) {
                vErrors = [err19];
              } else {
                vErrors.push(err19);
              }
              errors++;
            }
          }
          var _valid6 = _errs42 === errors;
          valid18 = valid18 || _valid6;
          if (!valid18) {
            const err20 = {};
            if (vErrors === null) {
              vErrors = [err20];
            } else {
              vErrors.push(err20);
            }
            errors++;
          } else {
            errors = _errs40;
            if (vErrors !== null) {
              if (_errs40) {
                vErrors.length = _errs40;
              } else {
                vErrors = null;
              }
            }
          }
          var valid17 = _errs39 === errors;
          if (valid17) {
            validate203.errors = [{ instancePath, schemaPath: "#/allOf/3/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
            return false;
          } else {
            errors = _errs38;
            if (vErrors !== null) {
              if (_errs38) {
                vErrors.length = _errs38;
              } else {
                vErrors = null;
              }
            }
          }
          if (errors === _errs37) {
            if (data && typeof data == "object" && !Array.isArray(data)) {
              if (data.stage !== void 0) {
                if (!(data.stage === "REPORT")) {
                  validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/3/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[3].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                  return false;
                }
              }
            }
          }
          var _valid5 = _errs37 === errors;
          valid15 = _valid5;
          if (valid15) {
            var props3 = {};
            props3.stage = true;
            props3.state = true;
          }
        }
        if (!valid15) {
          const err21 = { instancePath, schemaPath: "#/allOf/3/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
          if (vErrors === null) {
            vErrors = [err21];
          } else {
            vErrors.push(err21);
          }
          errors++;
          validate203.errors = vErrors;
          return false;
        }
        var valid0 = _errs33 === errors;
        if (valid0) {
          if (props0 !== true && props3 !== void 0) {
            if (props3 === true) {
              props0 = true;
            } else {
              props0 = props0 || {};
              Object.assign(props0, props3);
            }
          }
          const _errs44 = errors;
          const _errs45 = errors;
          let valid20 = true;
          const _errs46 = errors;
          if (data && typeof data == "object" && !Array.isArray(data)) {
            let missing12;
            if (data.state === void 0 && (missing12 = "state")) {
              const err22 = {};
              if (vErrors === null) {
                vErrors = [err22];
              } else {
                vErrors.push(err22);
              }
              errors++;
            } else {
              if (data.state !== void 0) {
                if ("SUCCEEDED" !== data.state) {
                  const err23 = {};
                  if (vErrors === null) {
                    vErrors = [err23];
                  } else {
                    vErrors.push(err23);
                  }
                  errors++;
                }
              }
            }
          }
          var _valid7 = _errs46 === errors;
          errors = _errs45;
          if (vErrors !== null) {
            if (_errs45) {
              vErrors.length = _errs45;
            } else {
              vErrors = null;
            }
          }
          if (_valid7) {
            const _errs48 = errors;
            if (data && typeof data == "object" && !Array.isArray(data)) {
              let missing13;
              if (data.reason === void 0 && (missing13 = "reason") || data.completedAt === void 0 && (missing13 = "completedAt")) {
                validate203.errors = [{ instancePath, schemaPath: "#/allOf/4/then/required", keyword: "required", params: { missingProperty: missing13 }, message: "must have required property '" + missing13 + "'" }];
                return false;
              } else {
                if (data.reason !== void 0) {
                  const _errs49 = errors;
                  if (!(data.reason === "COMPLETED")) {
                    validate203.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/4/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[4].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                    return false;
                  }
                  var valid22 = _errs49 === errors;
                } else {
                  var valid22 = true;
                }
                if (valid22) {
                  if (data.stage !== void 0) {
                    const _errs50 = errors;
                    if (!(data.stage === "REPORT")) {
                      validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/4/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[4].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                      return false;
                    }
                    var valid22 = _errs50 === errors;
                  } else {
                    var valid22 = true;
                  }
                }
              }
            }
            var _valid7 = _errs48 === errors;
            valid20 = _valid7;
            if (valid20) {
              var props4 = {};
              props4.reason = true;
              props4.stage = true;
              props4.state = true;
            }
          }
          if (!valid20) {
            const err24 = { instancePath, schemaPath: "#/allOf/4/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
            if (vErrors === null) {
              vErrors = [err24];
            } else {
              vErrors.push(err24);
            }
            errors++;
            validate203.errors = vErrors;
            return false;
          }
          var valid0 = _errs44 === errors;
          if (valid0) {
            if (props0 !== true && props4 !== void 0) {
              if (props4 === true) {
                props0 = true;
              } else {
                props0 = props0 || {};
                Object.assign(props0, props4);
              }
            }
            const _errs51 = errors;
            const _errs52 = errors;
            let valid23 = true;
            const _errs53 = errors;
            if (data && typeof data == "object" && !Array.isArray(data)) {
              let missing14;
              if (data.state === void 0 && (missing14 = "state")) {
                const err25 = {};
                if (vErrors === null) {
                  vErrors = [err25];
                } else {
                  vErrors.push(err25);
                }
                errors++;
              } else {
                if (data.state !== void 0) {
                  if ("FAILED" !== data.state) {
                    const err26 = {};
                    if (vErrors === null) {
                      vErrors = [err26];
                    } else {
                      vErrors.push(err26);
                    }
                    errors++;
                  }
                }
              }
            }
            var _valid8 = _errs53 === errors;
            errors = _errs52;
            if (vErrors !== null) {
              if (_errs52) {
                vErrors.length = _errs52;
              } else {
                vErrors = null;
              }
            }
            if (_valid8) {
              const _errs55 = errors;
              if (data && typeof data == "object" && !Array.isArray(data)) {
                let missing15;
                if (data.reason === void 0 && (missing15 = "reason") || data.completedAt === void 0 && (missing15 = "completedAt")) {
                  validate203.errors = [{ instancePath, schemaPath: "#/allOf/5/then/required", keyword: "required", params: { missingProperty: missing15 }, message: "must have required property '" + missing15 + "'" }];
                  return false;
                } else {
                  if (data.reason !== void 0) {
                    let data15 = data.reason;
                    const _errs56 = errors;
                    if (!(data15 === "SOURCE_UNAVAILABLE" || data15 === "COMMIT_MISMATCH" || data15 === "EXECUTOR_UNAVAILABLE" || data15 === "VERIFICATION_FAILED" || data15 === "DEADLINE_EXCEEDED" || data15 === "REPORT_UNAVAILABLE" || data15 === "REPORT_CONFLICT")) {
                      validate203.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/5/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[5].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                      return false;
                    }
                    var valid25 = _errs56 === errors;
                  } else {
                    var valid25 = true;
                  }
                  if (valid25) {
                    if (data.stage !== void 0) {
                      let data16 = data.stage;
                      const _errs57 = errors;
                      if (!(data16 === "RECEIVE" || data16 === "FETCH" || data16 === "VERIFY" || data16 === "REPORT")) {
                        validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/5/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[5].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                        return false;
                      }
                      var valid25 = _errs57 === errors;
                    } else {
                      var valid25 = true;
                    }
                  }
                }
              }
              var _valid8 = _errs55 === errors;
              valid23 = _valid8;
              if (valid23) {
                var props5 = {};
                props5.reason = true;
                props5.stage = true;
                props5.state = true;
              }
            }
            if (!valid23) {
              const err27 = { instancePath, schemaPath: "#/allOf/5/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
              if (vErrors === null) {
                vErrors = [err27];
              } else {
                vErrors.push(err27);
              }
              errors++;
              validate203.errors = vErrors;
              return false;
            }
            var valid0 = _errs51 === errors;
            if (valid0) {
              if (props0 !== true && props5 !== void 0) {
                if (props5 === true) {
                  props0 = true;
                } else {
                  props0 = props0 || {};
                  Object.assign(props0, props5);
                }
              }
              const _errs58 = errors;
              const _errs59 = errors;
              let valid26 = true;
              const _errs60 = errors;
              if (data && typeof data == "object" && !Array.isArray(data)) {
                let missing16;
                if (data.state === void 0 && (missing16 = "state")) {
                  const err28 = {};
                  if (vErrors === null) {
                    vErrors = [err28];
                  } else {
                    vErrors.push(err28);
                  }
                  errors++;
                } else {
                  if (data.state !== void 0) {
                    if ("CANCELLED" !== data.state) {
                      const err29 = {};
                      if (vErrors === null) {
                        vErrors = [err29];
                      } else {
                        vErrors.push(err29);
                      }
                      errors++;
                    }
                  }
                }
              }
              var _valid9 = _errs60 === errors;
              errors = _errs59;
              if (vErrors !== null) {
                if (_errs59) {
                  vErrors.length = _errs59;
                } else {
                  vErrors = null;
                }
              }
              if (_valid9) {
                const _errs62 = errors;
                if (data && typeof data == "object" && !Array.isArray(data)) {
                  let missing17;
                  if (data.reason === void 0 && (missing17 = "reason") || data.cancellationRequestedAt === void 0 && (missing17 = "cancellationRequestedAt") || data.completedAt === void 0 && (missing17 = "completedAt")) {
                    validate203.errors = [{ instancePath, schemaPath: "#/allOf/6/then/required", keyword: "required", params: { missingProperty: missing17 }, message: "must have required property '" + missing17 + "'" }];
                    return false;
                  } else {
                    if (data.reason !== void 0) {
                      const _errs63 = errors;
                      if (!(data.reason === "CANCELLED")) {
                        validate203.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/6/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[6].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                        return false;
                      }
                      var valid28 = _errs63 === errors;
                    } else {
                      var valid28 = true;
                    }
                    if (valid28) {
                      if (data.stage !== void 0) {
                        let data19 = data.stage;
                        const _errs64 = errors;
                        if (!(data19 === "RECEIVE" || data19 === "FETCH" || data19 === "VERIFY" || data19 === "REPORT")) {
                          validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/6/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[6].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                          return false;
                        }
                        var valid28 = _errs64 === errors;
                      } else {
                        var valid28 = true;
                      }
                    }
                  }
                }
                var _valid9 = _errs62 === errors;
                valid26 = _valid9;
                if (valid26) {
                  var props6 = {};
                  props6.reason = true;
                  props6.stage = true;
                  props6.state = true;
                }
              }
              if (!valid26) {
                const err30 = { instancePath, schemaPath: "#/allOf/6/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
                if (vErrors === null) {
                  vErrors = [err30];
                } else {
                  vErrors.push(err30);
                }
                errors++;
                validate203.errors = vErrors;
                return false;
              }
              var valid0 = _errs58 === errors;
              if (valid0) {
                if (props0 !== true && props6 !== void 0) {
                  if (props6 === true) {
                    props0 = true;
                  } else {
                    props0 = props0 || {};
                    Object.assign(props0, props6);
                  }
                }
                const _errs65 = errors;
                const _errs66 = errors;
                let valid29 = true;
                const _errs67 = errors;
                if (data && typeof data == "object" && !Array.isArray(data)) {
                  let missing18;
                  if (data.state === void 0 && (missing18 = "state")) {
                    const err31 = {};
                    if (vErrors === null) {
                      vErrors = [err31];
                    } else {
                      vErrors.push(err31);
                    }
                    errors++;
                  } else {
                    if (data.state !== void 0) {
                      if ("RECONCILING" !== data.state) {
                        const err32 = {};
                        if (vErrors === null) {
                          vErrors = [err32];
                        } else {
                          vErrors.push(err32);
                        }
                        errors++;
                      }
                    }
                  }
                }
                var _valid10 = _errs67 === errors;
                errors = _errs66;
                if (vErrors !== null) {
                  if (_errs66) {
                    vErrors.length = _errs66;
                  } else {
                    vErrors = null;
                  }
                }
                if (_valid10) {
                  const _errs69 = errors;
                  const _errs70 = errors;
                  const _errs71 = errors;
                  if (data && typeof data == "object" && !Array.isArray(data)) {
                    let missing19;
                    if (data.completedAt === void 0 && (missing19 = "completedAt")) {
                      const err33 = {};
                      if (vErrors === null) {
                        vErrors = [err33];
                      } else {
                        vErrors.push(err33);
                      }
                      errors++;
                    }
                  }
                  var valid31 = _errs71 === errors;
                  if (valid31) {
                    validate203.errors = [{ instancePath, schemaPath: "#/allOf/7/then/not", keyword: "not", params: {}, message: "must NOT be valid" }];
                    return false;
                  } else {
                    errors = _errs70;
                    if (vErrors !== null) {
                      if (_errs70) {
                        vErrors.length = _errs70;
                      } else {
                        vErrors = null;
                      }
                    }
                  }
                  if (errors === _errs69) {
                    if (data && typeof data == "object" && !Array.isArray(data)) {
                      let missing20;
                      if (data.reason === void 0 && (missing20 = "reason")) {
                        validate203.errors = [{ instancePath, schemaPath: "#/allOf/7/then/required", keyword: "required", params: { missingProperty: missing20 }, message: "must have required property '" + missing20 + "'" }];
                        return false;
                      } else {
                        if (data.reason !== void 0) {
                          const _errs72 = errors;
                          if (!(data.reason === "EXTERNAL_EFFECT_UNCERTAIN")) {
                            validate203.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/7/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[7].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                            return false;
                          }
                          var valid32 = _errs72 === errors;
                        } else {
                          var valid32 = true;
                        }
                        if (valid32) {
                          if (data.stage !== void 0) {
                            const _errs73 = errors;
                            if (!(data.stage === "REPORT")) {
                              validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/7/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[7].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                              return false;
                            }
                            var valid32 = _errs73 === errors;
                          } else {
                            var valid32 = true;
                          }
                        }
                      }
                    }
                  }
                  var _valid10 = _errs69 === errors;
                  valid29 = _valid10;
                  if (valid29) {
                    var props7 = {};
                    props7.reason = true;
                    props7.stage = true;
                    props7.state = true;
                  }
                }
                if (!valid29) {
                  const err34 = { instancePath, schemaPath: "#/allOf/7/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
                  if (vErrors === null) {
                    vErrors = [err34];
                  } else {
                    vErrors.push(err34);
                  }
                  errors++;
                  validate203.errors = vErrors;
                  return false;
                }
                var valid0 = _errs65 === errors;
                if (valid0) {
                  if (props0 !== true && props7 !== void 0) {
                    if (props7 === true) {
                      props0 = true;
                    } else {
                      props0 = props0 || {};
                      Object.assign(props0, props7);
                    }
                  }
                  const _errs74 = errors;
                  const _errs75 = errors;
                  let valid33 = true;
                  const _errs76 = errors;
                  if (data && typeof data == "object" && !Array.isArray(data)) {
                    let missing21;
                    if (data.state === void 0 && (missing21 = "state")) {
                      const err35 = {};
                      if (vErrors === null) {
                        vErrors = [err35];
                      } else {
                        vErrors.push(err35);
                      }
                      errors++;
                    } else {
                      if (data.state !== void 0) {
                        if ("MANUAL_INTERVENTION" !== data.state) {
                          const err36 = {};
                          if (vErrors === null) {
                            vErrors = [err36];
                          } else {
                            vErrors.push(err36);
                          }
                          errors++;
                        }
                      }
                    }
                  }
                  var _valid11 = _errs76 === errors;
                  errors = _errs75;
                  if (vErrors !== null) {
                    if (_errs75) {
                      vErrors.length = _errs75;
                    } else {
                      vErrors = null;
                    }
                  }
                  if (_valid11) {
                    const _errs78 = errors;
                    if (data && typeof data == "object" && !Array.isArray(data)) {
                      let missing22;
                      if (data.reason === void 0 && (missing22 = "reason") || data.completedAt === void 0 && (missing22 = "completedAt")) {
                        validate203.errors = [{ instancePath, schemaPath: "#/allOf/8/then/required", keyword: "required", params: { missingProperty: missing22 }, message: "must have required property '" + missing22 + "'" }];
                        return false;
                      } else {
                        if (data.reason !== void 0) {
                          const _errs79 = errors;
                          if (!(data.reason === "RECONCILIATION_EXHAUSTED")) {
                            validate203.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/8/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema57.allOf[8].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                            return false;
                          }
                          var valid35 = _errs79 === errors;
                        } else {
                          var valid35 = true;
                        }
                        if (valid35) {
                          if (data.stage !== void 0) {
                            const _errs80 = errors;
                            if (!(data.stage === "REPORT")) {
                              validate203.errors = [{ instancePath: instancePath + "/stage", schemaPath: "#/allOf/8/then/properties/stage/enum", keyword: "enum", params: { allowedValues: schema57.allOf[8].then.properties.stage.enum }, message: "must be equal to one of the allowed values" }];
                              return false;
                            }
                            var valid35 = _errs80 === errors;
                          } else {
                            var valid35 = true;
                          }
                        }
                      }
                    }
                    var _valid11 = _errs78 === errors;
                    valid33 = _valid11;
                    if (valid33) {
                      var props8 = {};
                      props8.reason = true;
                      props8.stage = true;
                      props8.state = true;
                    }
                  }
                  if (!valid33) {
                    const err37 = { instancePath, schemaPath: "#/allOf/8/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
                    if (vErrors === null) {
                      vErrors = [err37];
                    } else {
                      vErrors.push(err37);
                    }
                    errors++;
                    validate203.errors = vErrors;
                    return false;
                  }
                  var valid0 = _errs74 === errors;
                  if (valid0) {
                    if (props0 !== true && props8 !== void 0) {
                      if (props8 === true) {
                        props0 = true;
                      } else {
                        props0 = props0 || {};
                        Object.assign(props0, props8);
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing23;
      if (data.observedAt === void 0 && (missing23 = "observedAt") || data.resourceVersion === void 0 && (missing23 = "resourceVersion") || data.stage === void 0 && (missing23 = "stage") || data.state === void 0 && (missing23 = "state")) {
        validate203.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing23 }, message: "must have required property '" + missing23 + "'" }];
        return false;
      } else {
        const _errs81 = errors;
        for (const key0 in data) {
          if (!(key0 === "cancellationRequestedAt" || key0 === "completedAt" || key0 === "observedAt" || key0 === "reason" || key0 === "resourceVersion" || key0 === "stage" || key0 === "state")) {
            validate203.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs81 === errors) {
          if (data.cancellationRequestedAt !== void 0) {
            const _errs82 = errors;
            if (!validate91(data.cancellationRequestedAt, { instancePath: instancePath + "/cancellationRequestedAt", parentData: data, parentDataProperty: "cancellationRequestedAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
              errors = vErrors.length;
            }
            var valid36 = _errs82 === errors;
          } else {
            var valid36 = true;
          }
          if (valid36) {
            if (data.completedAt !== void 0) {
              const _errs83 = errors;
              if (!validate91(data.completedAt, { instancePath: instancePath + "/completedAt", parentData: data, parentDataProperty: "completedAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid36 = _errs83 === errors;
            } else {
              var valid36 = true;
            }
            if (valid36) {
              if (data.observedAt !== void 0) {
                const _errs84 = errors;
                if (!validate91(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                  errors = vErrors.length;
                }
                var valid36 = _errs84 === errors;
              } else {
                var valid36 = true;
              }
              if (valid36) {
                if (data.reason !== void 0) {
                  const _errs85 = errors;
                  if (!validate175(data.reason, { instancePath: instancePath + "/reason", parentData: data, parentDataProperty: "reason", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate175.errors : vErrors.concat(validate175.errors);
                    errors = vErrors.length;
                  }
                  var valid36 = _errs85 === errors;
                } else {
                  var valid36 = true;
                }
                if (valid36) {
                  if (data.resourceVersion !== void 0) {
                    let data30 = data.resourceVersion;
                    const _errs86 = errors;
                    if (!(typeof data30 == "number" && (!(data30 % 1) && !isNaN(data30)))) {
                      validate203.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                      return false;
                    }
                    if (errors === _errs86) {
                      if (typeof data30 == "number") {
                        if (data30 > 9007199254740991 || isNaN(data30)) {
                          validate203.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                          return false;
                        } else {
                          if (data30 < 1 || isNaN(data30)) {
                            validate203.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                            return false;
                          }
                        }
                      }
                    }
                    var valid36 = _errs86 === errors;
                  } else {
                    var valid36 = true;
                  }
                  if (valid36) {
                    if (data.stage !== void 0) {
                      const _errs88 = errors;
                      if (!validate177(data.stage, { instancePath: instancePath + "/stage", parentData: data, parentDataProperty: "stage", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate177.errors : vErrors.concat(validate177.errors);
                        errors = vErrors.length;
                      }
                      var valid36 = _errs88 === errors;
                    } else {
                      var valid36 = true;
                    }
                    if (valid36) {
                      if (data.state !== void 0) {
                        const _errs89 = errors;
                        if (!validate179(data.state, { instancePath: instancePath + "/state", parentData: data, parentDataProperty: "state", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate179.errors : vErrors.concat(validate179.errors);
                          errors = vErrors.length;
                        }
                        var valid36 = _errs89 === errors;
                      } else {
                        var valid36 = true;
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
      validate203.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate203.errors = vErrors;
  return errors === 0;
}
validate203.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ReporterPolicy = validate210;
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
  if (typeof data !== "string") {
    validate210.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CHANGE_CHECK_V1")) {
    validate210.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema27.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate210.errors = vErrors;
  return errors === 0;
}
validate210.evaluated = { "dynamicProps": false, "dynamicItems": false };
var RepositoryBinding = validate211;
var schema73 = { "additionalProperties": false, "allOf": [{ "if": { "properties": { "health": { "const": "PENDING" } }, "required": ["health"] }, "then": { "properties": { "reason": { "enum": ["CONFIGURATION_CHANGED", "CONNECTION_NOT_READY"] } }, "required": ["reason"] } }, { "if": { "properties": { "health": { "const": "READY" } }, "required": ["health"] }, "then": { "properties": { "reason": { "enum": ["OBSERVED"] } }, "required": ["reason"] } }, { "if": { "properties": { "health": { "const": "UNAVAILABLE" } }, "required": ["health"] }, "then": { "properties": { "reason": { "enum": ["REPOSITORY_UNAVAILABLE", "IDENTITY_MISMATCH", "FETCH_PERMISSION_DENIED", "REPORT_PERMISSION_DENIED"] } }, "required": ["reason"] } }], "properties": { "health": { "$ref": "#/components/schemas/RepositoryBindingHealth" }, "observedAt": { "$ref": "#/components/schemas/Timestamp" }, "reason": { "$ref": "#/components/schemas/RepositoryBindingHealthReason" } }, "required": ["health", "observedAt", "reason"], "type": "object" };
var schema74 = { "enum": ["PENDING", "READY", "UNAVAILABLE"], "type": "string" };
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
  if (typeof data !== "string") {
    validate216.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PENDING" || data === "READY" || data === "UNAVAILABLE")) {
    validate216.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema74.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate216.errors = vErrors;
  return errors === 0;
}
validate216.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema75 = { "enum": ["CONFIGURATION_CHANGED", "CONNECTION_NOT_READY", "OBSERVED", "REPOSITORY_UNAVAILABLE", "IDENTITY_MISMATCH", "FETCH_PERMISSION_DENIED", "REPORT_PERMISSION_DENIED"], "type": "string" };
function validate219(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate219.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate219.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CONFIGURATION_CHANGED" || data === "CONNECTION_NOT_READY" || data === "OBSERVED" || data === "REPOSITORY_UNAVAILABLE" || data === "IDENTITY_MISMATCH" || data === "FETCH_PERMISSION_DENIED" || data === "REPORT_PERMISSION_DENIED")) {
    validate219.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema75.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate219.errors = vErrors;
  return errors === 0;
}
validate219.evaluated = { "dynamicProps": false, "dynamicItems": false };
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
  const _errs1 = errors;
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.health === void 0 && (missing0 = "health")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.health !== void 0) {
        if ("PENDING" !== data.health) {
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
      let missing1;
      if (data.reason === void 0 && (missing1 = "reason")) {
        validate215.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
        return false;
      } else {
        if (data.reason !== void 0) {
          let data1 = data.reason;
          if (!(data1 === "CONFIGURATION_CHANGED" || data1 === "CONNECTION_NOT_READY")) {
            validate215.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/0/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema73.allOf[0].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
            return false;
          }
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.reason = true;
      props0.health = true;
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
    validate215.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs7 = errors;
    const _errs8 = errors;
    let valid4 = true;
    const _errs9 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.health === void 0 && (missing2 = "health")) {
        const err3 = {};
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      } else {
        if (data.health !== void 0) {
          if ("READY" !== data.health) {
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
        let missing3;
        if (data.reason === void 0 && (missing3 = "reason")) {
          validate215.errors = [{ instancePath, schemaPath: "#/allOf/1/then/required", keyword: "required", params: { missingProperty: missing3 }, message: "must have required property '" + missing3 + "'" }];
          return false;
        } else {
          if (data.reason !== void 0) {
            if (!(data.reason === "OBSERVED")) {
              validate215.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/1/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema73.allOf[1].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
              return false;
            }
          }
        }
      }
      var _valid1 = _errs11 === errors;
      valid4 = _valid1;
      if (valid4) {
        var props1 = {};
        props1.reason = true;
        props1.health = true;
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
      validate215.errors = vErrors;
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
      const _errs13 = errors;
      const _errs14 = errors;
      let valid7 = true;
      const _errs15 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing4;
        if (data.health === void 0 && (missing4 = "health")) {
          const err6 = {};
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        } else {
          if (data.health !== void 0) {
            if ("UNAVAILABLE" !== data.health) {
              const err7 = {};
              if (vErrors === null) {
                vErrors = [err7];
              } else {
                vErrors.push(err7);
              }
              errors++;
            }
          }
        }
      }
      var _valid2 = _errs15 === errors;
      errors = _errs14;
      if (vErrors !== null) {
        if (_errs14) {
          vErrors.length = _errs14;
        } else {
          vErrors = null;
        }
      }
      if (_valid2) {
        const _errs17 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing5;
          if (data.reason === void 0 && (missing5 = "reason")) {
            validate215.errors = [{ instancePath, schemaPath: "#/allOf/2/then/required", keyword: "required", params: { missingProperty: missing5 }, message: "must have required property '" + missing5 + "'" }];
            return false;
          } else {
            if (data.reason !== void 0) {
              let data5 = data.reason;
              if (!(data5 === "REPOSITORY_UNAVAILABLE" || data5 === "IDENTITY_MISMATCH" || data5 === "FETCH_PERMISSION_DENIED" || data5 === "REPORT_PERMISSION_DENIED")) {
                validate215.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/2/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema73.allOf[2].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
            }
          }
        }
        var _valid2 = _errs17 === errors;
        valid7 = _valid2;
        if (valid7) {
          var props2 = {};
          props2.reason = true;
          props2.health = true;
        }
      }
      if (!valid7) {
        const err8 = { instancePath, schemaPath: "#/allOf/2/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
        validate215.errors = vErrors;
        return false;
      }
      var valid0 = _errs13 === errors;
      if (valid0) {
        if (props0 !== true && props2 !== void 0) {
          if (props2 === true) {
            props0 = true;
          } else {
            props0 = props0 || {};
            Object.assign(props0, props2);
          }
        }
      }
    }
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing6;
      if (data.health === void 0 && (missing6 = "health") || data.observedAt === void 0 && (missing6 = "observedAt") || data.reason === void 0 && (missing6 = "reason")) {
        validate215.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing6 }, message: "must have required property '" + missing6 + "'" }];
        return false;
      } else {
        const _errs19 = errors;
        for (const key0 in data) {
          if (!(key0 === "health" || key0 === "observedAt" || key0 === "reason")) {
            validate215.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs19 === errors) {
          if (data.health !== void 0) {
            const _errs20 = errors;
            if (!validate216(data.health, { instancePath: instancePath + "/health", parentData: data, parentDataProperty: "health", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate216.errors : vErrors.concat(validate216.errors);
              errors = vErrors.length;
            }
            var valid10 = _errs20 === errors;
          } else {
            var valid10 = true;
          }
          if (valid10) {
            if (data.observedAt !== void 0) {
              const _errs21 = errors;
              if (!validate91(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid10 = _errs21 === errors;
            } else {
              var valid10 = true;
            }
            if (valid10) {
              if (data.reason !== void 0) {
                const _errs22 = errors;
                if (!validate219(data.reason, { instancePath: instancePath + "/reason", parentData: data, parentDataProperty: "reason", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate219.errors : vErrors.concat(validate219.errors);
                  errors = vErrors.length;
                }
                var valid10 = _errs22 === errors;
              } else {
                var valid10 = true;
              }
            }
          }
        }
      }
    } else {
      validate215.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate215.errors = vErrors;
  return errors === 0;
}
validate215.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.contentDigest === void 0 && (missing0 = "contentDigest") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata") || data.projectId === void 0 && (missing0 = "projectId") || data.spec === void 0 && (missing0 = "spec") || data.status === void 0 && (missing0 = "status")) {
        validate211.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "contentDigest" || key0 === "kind" || key0 === "metadata" || key0 === "projectId" || key0 === "spec" || key0 === "status")) {
            validate211.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
              validate211.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.contentDigest !== void 0) {
              let data1 = data.contentDigest;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (!pattern18.test(data1)) {
                    validate211.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/pattern", keyword: "pattern", params: { pattern: "^sha256:[0-9a-f]{64}$" }, message: 'must match pattern "^sha256:[0-9a-f]{64}$"' }];
                    return false;
                  }
                } else {
                  validate211.errors = [{ instancePath: instancePath + "/contentDigest", schemaPath: "#/properties/contentDigest/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.kind !== void 0) {
                const _errs5 = errors;
                if ("RepositoryBinding" !== data.kind) {
                  validate211.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "RepositoryBinding" }, message: "must be equal to constant" }];
                  return false;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.metadata !== void 0) {
                  const _errs6 = errors;
                  if (!validate90(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate90.errors : vErrors.concat(validate90.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs6 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.projectId !== void 0) {
                    const _errs7 = errors;
                    if (!validate57(data.projectId, { instancePath: instancePath + "/projectId", parentData: data, parentDataProperty: "projectId", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs7 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.spec !== void 0) {
                      const _errs8 = errors;
                      if (!validate76(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate76.errors : vErrors.concat(validate76.errors);
                        errors = vErrors.length;
                      }
                      var valid0 = _errs8 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.status !== void 0) {
                        const _errs9 = errors;
                        if (!validate215(data.status, { instancePath: instancePath + "/status", parentData: data, parentDataProperty: "status", rootData, dynamicAnchors })) {
                          vErrors = vErrors === null ? validate215.errors : vErrors.concat(validate215.errors);
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
      validate211.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate211.errors = vErrors;
  return errors === 0;
}
validate211.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var RepositoryBindingHealth = validate222;
function validate222(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate222.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate222.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PENDING" || data === "READY" || data === "UNAVAILABLE")) {
    validate222.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema74.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate222.errors = vErrors;
  return errors === 0;
}
validate222.evaluated = { "dynamicProps": false, "dynamicItems": false };
var RepositoryBindingHealthReason = validate223;
function validate223(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate223.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate223.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CONFIGURATION_CHANGED" || data === "CONNECTION_NOT_READY" || data === "OBSERVED" || data === "REPOSITORY_UNAVAILABLE" || data === "IDENTITY_MISMATCH" || data === "FETCH_PERMISSION_DENIED" || data === "REPORT_PERMISSION_DENIED")) {
    validate223.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema75.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate223.errors = vErrors;
  return errors === 0;
}
validate223.evaluated = { "dynamicProps": false, "dynamicItems": false };
var RepositoryBindingSpec = validate224;
function validate224(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate224.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.externalRepositoryId === void 0 && (missing0 = "externalRepositoryId") || data.repositoryPath === void 0 && (missing0 = "repositoryPath") || data.sourceConnectionId === void 0 && (missing0 = "sourceConnectionId") || data.trustedDefaultBranch === void 0 && (missing0 = "trustedDefaultBranch")) {
        validate224.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "externalRepositoryId" || key0 === "repositoryPath" || key0 === "sourceConnectionId" || key0 === "trustedDefaultBranch")) {
            validate224.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.externalRepositoryId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.externalRepositoryId, { instancePath: instancePath + "/externalRepositoryId", parentData: data, parentDataProperty: "externalRepositoryId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.repositoryPath !== void 0) {
              let data1 = data.repositoryPath;
              const _errs3 = errors;
              if (errors === _errs3) {
                if (typeof data1 === "string") {
                  if (func1(data1) > 257) {
                    validate224.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/maxLength", keyword: "maxLength", params: { limit: 257 }, message: "must NOT have more than 257 characters" }];
                    return false;
                  } else {
                    if (func1(data1) < 3) {
                      validate224.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/minLength", keyword: "minLength", params: { limit: 3 }, message: "must NOT have fewer than 3 characters" }];
                      return false;
                    } else {
                      if (!pattern9.test(data1)) {
                        validate224.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"' }];
                        return false;
                      }
                    }
                  }
                } else {
                  validate224.errors = [{ instancePath: instancePath + "/repositoryPath", schemaPath: "#/properties/repositoryPath/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                  return false;
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.sourceConnectionId !== void 0) {
                const _errs5 = errors;
                if (!validate57(data.sourceConnectionId, { instancePath: instancePath + "/sourceConnectionId", parentData: data, parentDataProperty: "sourceConnectionId", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs5 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.trustedDefaultBranch !== void 0) {
                  let data3 = data.trustedDefaultBranch;
                  const _errs6 = errors;
                  const _errs8 = errors;
                  const _errs9 = errors;
                  if (typeof data3 === "string") {
                    if (!pattern10.test(data3)) {
                      const err0 = {};
                      if (vErrors === null) {
                        vErrors = [err0];
                      } else {
                        vErrors.push(err0);
                      }
                      errors++;
                    }
                  }
                  var valid1 = _errs9 === errors;
                  if (valid1) {
                    validate224.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/not", keyword: "not", params: {}, message: "must NOT be valid" }];
                    return false;
                  } else {
                    errors = _errs8;
                    if (vErrors !== null) {
                      if (_errs8) {
                        vErrors.length = _errs8;
                      } else {
                        vErrors = null;
                      }
                    }
                  }
                  if (errors === _errs6) {
                    if (typeof data3 === "string") {
                      if (func1(data3) > 128) {
                        validate224.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
                        return false;
                      } else {
                        if (func1(data3) < 1) {
                          validate224.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                          return false;
                        } else {
                          if (!pattern11.test(data3)) {
                            validate224.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$"' }];
                            return false;
                          }
                        }
                      }
                    } else {
                      validate224.errors = [{ instancePath: instancePath + "/trustedDefaultBranch", schemaPath: "#/properties/trustedDefaultBranch/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                      return false;
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
      }
    } else {
      validate224.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate224.errors = vErrors;
  return errors === 0;
}
validate224.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var RepositoryBindingStatus = validate227;
function validate227(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate227.evaluated;
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
    if (data.health === void 0 && (missing0 = "health")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.health !== void 0) {
        if ("PENDING" !== data.health) {
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
      let missing1;
      if (data.reason === void 0 && (missing1 = "reason")) {
        validate227.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
        return false;
      } else {
        if (data.reason !== void 0) {
          let data1 = data.reason;
          if (!(data1 === "CONFIGURATION_CHANGED" || data1 === "CONNECTION_NOT_READY")) {
            validate227.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/0/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema73.allOf[0].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
            return false;
          }
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.reason = true;
      props0.health = true;
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
    validate227.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs7 = errors;
    const _errs8 = errors;
    let valid4 = true;
    const _errs9 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.health === void 0 && (missing2 = "health")) {
        const err3 = {};
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      } else {
        if (data.health !== void 0) {
          if ("READY" !== data.health) {
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
        let missing3;
        if (data.reason === void 0 && (missing3 = "reason")) {
          validate227.errors = [{ instancePath, schemaPath: "#/allOf/1/then/required", keyword: "required", params: { missingProperty: missing3 }, message: "must have required property '" + missing3 + "'" }];
          return false;
        } else {
          if (data.reason !== void 0) {
            if (!(data.reason === "OBSERVED")) {
              validate227.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/1/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema73.allOf[1].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
              return false;
            }
          }
        }
      }
      var _valid1 = _errs11 === errors;
      valid4 = _valid1;
      if (valid4) {
        var props1 = {};
        props1.reason = true;
        props1.health = true;
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
      validate227.errors = vErrors;
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
      const _errs13 = errors;
      const _errs14 = errors;
      let valid7 = true;
      const _errs15 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing4;
        if (data.health === void 0 && (missing4 = "health")) {
          const err6 = {};
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        } else {
          if (data.health !== void 0) {
            if ("UNAVAILABLE" !== data.health) {
              const err7 = {};
              if (vErrors === null) {
                vErrors = [err7];
              } else {
                vErrors.push(err7);
              }
              errors++;
            }
          }
        }
      }
      var _valid2 = _errs15 === errors;
      errors = _errs14;
      if (vErrors !== null) {
        if (_errs14) {
          vErrors.length = _errs14;
        } else {
          vErrors = null;
        }
      }
      if (_valid2) {
        const _errs17 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing5;
          if (data.reason === void 0 && (missing5 = "reason")) {
            validate227.errors = [{ instancePath, schemaPath: "#/allOf/2/then/required", keyword: "required", params: { missingProperty: missing5 }, message: "must have required property '" + missing5 + "'" }];
            return false;
          } else {
            if (data.reason !== void 0) {
              let data5 = data.reason;
              if (!(data5 === "REPOSITORY_UNAVAILABLE" || data5 === "IDENTITY_MISMATCH" || data5 === "FETCH_PERMISSION_DENIED" || data5 === "REPORT_PERMISSION_DENIED")) {
                validate227.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/2/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema73.allOf[2].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
            }
          }
        }
        var _valid2 = _errs17 === errors;
        valid7 = _valid2;
        if (valid7) {
          var props2 = {};
          props2.reason = true;
          props2.health = true;
        }
      }
      if (!valid7) {
        const err8 = { instancePath, schemaPath: "#/allOf/2/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
        validate227.errors = vErrors;
        return false;
      }
      var valid0 = _errs13 === errors;
      if (valid0) {
        if (props0 !== true && props2 !== void 0) {
          if (props2 === true) {
            props0 = true;
          } else {
            props0 = props0 || {};
            Object.assign(props0, props2);
          }
        }
      }
    }
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing6;
      if (data.health === void 0 && (missing6 = "health") || data.observedAt === void 0 && (missing6 = "observedAt") || data.reason === void 0 && (missing6 = "reason")) {
        validate227.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing6 }, message: "must have required property '" + missing6 + "'" }];
        return false;
      } else {
        const _errs19 = errors;
        for (const key0 in data) {
          if (!(key0 === "health" || key0 === "observedAt" || key0 === "reason")) {
            validate227.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs19 === errors) {
          if (data.health !== void 0) {
            const _errs20 = errors;
            if (!validate216(data.health, { instancePath: instancePath + "/health", parentData: data, parentDataProperty: "health", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate216.errors : vErrors.concat(validate216.errors);
              errors = vErrors.length;
            }
            var valid10 = _errs20 === errors;
          } else {
            var valid10 = true;
          }
          if (valid10) {
            if (data.observedAt !== void 0) {
              const _errs21 = errors;
              if (!validate91(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid10 = _errs21 === errors;
            } else {
              var valid10 = true;
            }
            if (valid10) {
              if (data.reason !== void 0) {
                const _errs22 = errors;
                if (!validate219(data.reason, { instancePath: instancePath + "/reason", parentData: data, parentDataProperty: "reason", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate219.errors : vErrors.concat(validate219.errors);
                  errors = vErrors.length;
                }
                var valid10 = _errs22 === errors;
              } else {
                var valid10 = true;
              }
            }
          }
        }
      }
    } else {
      validate227.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate227.errors = vErrors;
  return errors === 0;
}
validate227.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ResourceID = validate231;
function validate231(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate231.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (typeof data === "string") {
      if (func1(data) > 128) {
        validate231.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate231.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern5.test(data)) {
            validate231.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"' }];
            return false;
          }
        }
      }
    } else {
      validate231.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate231.errors = vErrors;
  return errors === 0;
}
validate231.evaluated = { "dynamicProps": false, "dynamicItems": false };
var ResourceMetadata = validate232;
function validate232(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate232.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.createdAt === void 0 && (missing0 = "createdAt") || data.id === void 0 && (missing0 = "id") || data.name === void 0 && (missing0 = "name") || data.resourceVersion === void 0 && (missing0 = "resourceVersion") || data.scope === void 0 && (missing0 = "scope") || data.updatedAt === void 0 && (missing0 = "updatedAt")) {
        validate232.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "createdAt" || key0 === "id" || key0 === "name" || key0 === "resourceVersion" || key0 === "scope" || key0 === "updatedAt")) {
            validate232.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.createdAt !== void 0) {
            const _errs2 = errors;
            if (!validate91(data.createdAt, { instancePath: instancePath + "/createdAt", parentData: data, parentDataProperty: "createdAt", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
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
              if (data.name !== void 0) {
                let data2 = data.name;
                const _errs4 = errors;
                if (errors === _errs4) {
                  if (typeof data2 === "string") {
                    if (func1(data2) > 63) {
                      validate232.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/maxLength", keyword: "maxLength", params: { limit: 63 }, message: "must NOT have more than 63 characters" }];
                      return false;
                    } else {
                      if (func1(data2) < 1) {
                        validate232.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                        return false;
                      } else {
                        if (!pattern6.test(data2)) {
                          validate232.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/pattern", keyword: "pattern", params: { pattern: "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$" }, message: 'must match pattern "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"' }];
                          return false;
                        }
                      }
                    }
                  } else {
                    validate232.errors = [{ instancePath: instancePath + "/name", schemaPath: "#/properties/name/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.resourceVersion !== void 0) {
                  let data3 = data.resourceVersion;
                  const _errs6 = errors;
                  if (!(typeof data3 == "number" && (!(data3 % 1) && !isNaN(data3)))) {
                    validate232.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                    return false;
                  }
                  if (errors === _errs6) {
                    if (typeof data3 == "number") {
                      if (data3 > 9007199254740991 || isNaN(data3)) {
                        validate232.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/maximum", keyword: "maximum", params: { comparison: "<=", limit: 9007199254740991 }, message: "must be <= 9007199254740991" }];
                        return false;
                      } else {
                        if (data3 < 1 || isNaN(data3)) {
                          validate232.errors = [{ instancePath: instancePath + "/resourceVersion", schemaPath: "#/properties/resourceVersion/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
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
                    if (!validate94(data.scope, { instancePath: instancePath + "/scope", parentData: data, parentDataProperty: "scope", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate94.errors : vErrors.concat(validate94.errors);
                      errors = vErrors.length;
                    }
                    var valid0 = _errs8 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.updatedAt !== void 0) {
                      const _errs9 = errors;
                      if (!validate91(data.updatedAt, { instancePath: instancePath + "/updatedAt", parentData: data, parentDataProperty: "updatedAt", rootData, dynamicAnchors })) {
                        vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
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
    } else {
      validate232.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate232.errors = vErrors;
  return errors === 0;
}
validate232.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var ResourceScope = validate237;
function validate237(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate237.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.tenantId === void 0 && (missing0 = "tenantId")) {
        validate237.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "tenantId")) {
            validate237.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.tenantId !== void 0) {
            if (!validate95(data.tenantId, { instancePath: instancePath + "/tenantId", parentData: data, parentDataProperty: "tenantId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate95.errors : vErrors.concat(validate95.errors);
              errors = vErrors.length;
            }
          }
        }
      }
    } else {
      validate237.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate237.errors = vErrors;
  return errors === 0;
}
validate237.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var SourceConnection = validate239;
var schema84 = { "additionalProperties": false, "allOf": [{ "if": { "properties": { "health": { "const": "PENDING" } }, "required": ["health"] }, "then": { "properties": { "reason": { "enum": ["CONFIGURATION_CHANGED"] } }, "required": ["reason"] } }, { "if": { "properties": { "health": { "const": "READY" } }, "required": ["health"] }, "then": { "properties": { "reason": { "enum": ["OBSERVED"] } }, "required": ["reason"] } }, { "if": { "properties": { "health": { "const": "UNAVAILABLE" } }, "required": ["health"] }, "then": { "properties": { "reason": { "enum": ["SECRET_UNAVAILABLE", "PROVIDER_UNAVAILABLE", "PROVIDER_UNSUPPORTED", "CREDENTIAL_REJECTED"] } }, "required": ["reason"] } }], "properties": { "health": { "$ref": "#/components/schemas/SourceConnectionHealth" }, "observedAt": { "$ref": "#/components/schemas/Timestamp" }, "reason": { "$ref": "#/components/schemas/SourceConnectionHealthReason" } }, "required": ["health", "observedAt", "reason"], "type": "object" };
var schema85 = { "enum": ["PENDING", "READY", "UNAVAILABLE"], "type": "string" };
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
  if (typeof data !== "string") {
    validate243.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PENDING" || data === "READY" || data === "UNAVAILABLE")) {
    validate243.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema85.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate243.errors = vErrors;
  return errors === 0;
}
validate243.evaluated = { "dynamicProps": false, "dynamicItems": false };
var schema86 = { "enum": ["CONFIGURATION_CHANGED", "OBSERVED", "SECRET_UNAVAILABLE", "PROVIDER_UNAVAILABLE", "PROVIDER_UNSUPPORTED", "CREDENTIAL_REJECTED"], "type": "string" };
function validate246(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate246.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate246.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CONFIGURATION_CHANGED" || data === "OBSERVED" || data === "SECRET_UNAVAILABLE" || data === "PROVIDER_UNAVAILABLE" || data === "PROVIDER_UNSUPPORTED" || data === "CREDENTIAL_REJECTED")) {
    validate246.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema86.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate246.errors = vErrors;
  return errors === 0;
}
validate246.evaluated = { "dynamicProps": false, "dynamicItems": false };
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
  const _errs1 = errors;
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.health === void 0 && (missing0 = "health")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.health !== void 0) {
        if ("PENDING" !== data.health) {
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
      let missing1;
      if (data.reason === void 0 && (missing1 = "reason")) {
        validate242.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
        return false;
      } else {
        if (data.reason !== void 0) {
          if (!(data.reason === "CONFIGURATION_CHANGED")) {
            validate242.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/0/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema84.allOf[0].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
            return false;
          }
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.reason = true;
      props0.health = true;
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
    validate242.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs7 = errors;
    const _errs8 = errors;
    let valid4 = true;
    const _errs9 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.health === void 0 && (missing2 = "health")) {
        const err3 = {};
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      } else {
        if (data.health !== void 0) {
          if ("READY" !== data.health) {
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
        let missing3;
        if (data.reason === void 0 && (missing3 = "reason")) {
          validate242.errors = [{ instancePath, schemaPath: "#/allOf/1/then/required", keyword: "required", params: { missingProperty: missing3 }, message: "must have required property '" + missing3 + "'" }];
          return false;
        } else {
          if (data.reason !== void 0) {
            if (!(data.reason === "OBSERVED")) {
              validate242.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/1/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema84.allOf[1].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
              return false;
            }
          }
        }
      }
      var _valid1 = _errs11 === errors;
      valid4 = _valid1;
      if (valid4) {
        var props1 = {};
        props1.reason = true;
        props1.health = true;
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
      validate242.errors = vErrors;
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
      const _errs13 = errors;
      const _errs14 = errors;
      let valid7 = true;
      const _errs15 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing4;
        if (data.health === void 0 && (missing4 = "health")) {
          const err6 = {};
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        } else {
          if (data.health !== void 0) {
            if ("UNAVAILABLE" !== data.health) {
              const err7 = {};
              if (vErrors === null) {
                vErrors = [err7];
              } else {
                vErrors.push(err7);
              }
              errors++;
            }
          }
        }
      }
      var _valid2 = _errs15 === errors;
      errors = _errs14;
      if (vErrors !== null) {
        if (_errs14) {
          vErrors.length = _errs14;
        } else {
          vErrors = null;
        }
      }
      if (_valid2) {
        const _errs17 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing5;
          if (data.reason === void 0 && (missing5 = "reason")) {
            validate242.errors = [{ instancePath, schemaPath: "#/allOf/2/then/required", keyword: "required", params: { missingProperty: missing5 }, message: "must have required property '" + missing5 + "'" }];
            return false;
          } else {
            if (data.reason !== void 0) {
              let data5 = data.reason;
              if (!(data5 === "SECRET_UNAVAILABLE" || data5 === "PROVIDER_UNAVAILABLE" || data5 === "PROVIDER_UNSUPPORTED" || data5 === "CREDENTIAL_REJECTED")) {
                validate242.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/2/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema84.allOf[2].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
            }
          }
        }
        var _valid2 = _errs17 === errors;
        valid7 = _valid2;
        if (valid7) {
          var props2 = {};
          props2.reason = true;
          props2.health = true;
        }
      }
      if (!valid7) {
        const err8 = { instancePath, schemaPath: "#/allOf/2/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
        validate242.errors = vErrors;
        return false;
      }
      var valid0 = _errs13 === errors;
      if (valid0) {
        if (props0 !== true && props2 !== void 0) {
          if (props2 === true) {
            props0 = true;
          } else {
            props0 = props0 || {};
            Object.assign(props0, props2);
          }
        }
      }
    }
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing6;
      if (data.health === void 0 && (missing6 = "health") || data.observedAt === void 0 && (missing6 = "observedAt") || data.reason === void 0 && (missing6 = "reason")) {
        validate242.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing6 }, message: "must have required property '" + missing6 + "'" }];
        return false;
      } else {
        const _errs19 = errors;
        for (const key0 in data) {
          if (!(key0 === "health" || key0 === "observedAt" || key0 === "reason")) {
            validate242.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs19 === errors) {
          if (data.health !== void 0) {
            const _errs20 = errors;
            if (!validate243(data.health, { instancePath: instancePath + "/health", parentData: data, parentDataProperty: "health", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate243.errors : vErrors.concat(validate243.errors);
              errors = vErrors.length;
            }
            var valid10 = _errs20 === errors;
          } else {
            var valid10 = true;
          }
          if (valid10) {
            if (data.observedAt !== void 0) {
              const _errs21 = errors;
              if (!validate91(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid10 = _errs21 === errors;
            } else {
              var valid10 = true;
            }
            if (valid10) {
              if (data.reason !== void 0) {
                const _errs22 = errors;
                if (!validate246(data.reason, { instancePath: instancePath + "/reason", parentData: data, parentDataProperty: "reason", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate246.errors : vErrors.concat(validate246.errors);
                  errors = vErrors.length;
                }
                var valid10 = _errs22 === errors;
              } else {
                var valid10 = true;
              }
            }
          }
        }
      }
    } else {
      validate242.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate242.errors = vErrors;
  return errors === 0;
}
validate242.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
function validate239(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate239.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.apiVersion === void 0 && (missing0 = "apiVersion") || data.kind === void 0 && (missing0 = "kind") || data.metadata === void 0 && (missing0 = "metadata") || data.spec === void 0 && (missing0 = "spec") || data.status === void 0 && (missing0 = "status")) {
        validate239.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "apiVersion" || key0 === "kind" || key0 === "metadata" || key0 === "spec" || key0 === "status")) {
            validate239.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.apiVersion !== void 0) {
            const _errs2 = errors;
            if ("devops.matrix.xiak.com/v1" !== data.apiVersion) {
              validate239.errors = [{ instancePath: instancePath + "/apiVersion", schemaPath: "#/properties/apiVersion/const", keyword: "const", params: { allowedValue: "devops.matrix.xiak.com/v1" }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs3 = errors;
              if ("SourceConnection" !== data.kind) {
                validate239.errors = [{ instancePath: instancePath + "/kind", schemaPath: "#/properties/kind/const", keyword: "const", params: { allowedValue: "SourceConnection" }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.metadata !== void 0) {
                const _errs4 = errors;
                if (!validate90(data.metadata, { instancePath: instancePath + "/metadata", parentData: data, parentDataProperty: "metadata", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate90.errors : vErrors.concat(validate90.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.spec !== void 0) {
                  const _errs5 = errors;
                  if (!validate82(data.spec, { instancePath: instancePath + "/spec", parentData: data, parentDataProperty: "spec", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate82.errors : vErrors.concat(validate82.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.status !== void 0) {
                    const _errs6 = errors;
                    if (!validate242(data.status, { instancePath: instancePath + "/status", parentData: data, parentDataProperty: "status", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate242.errors : vErrors.concat(validate242.errors);
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
      }
    } else {
      validate239.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate239.errors = vErrors;
  return errors === 0;
}
validate239.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var SourceConnectionHealth = validate249;
function validate249(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate249.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate249.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "PENDING" || data === "READY" || data === "UNAVAILABLE")) {
    validate249.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema85.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate249.errors = vErrors;
  return errors === 0;
}
validate249.evaluated = { "dynamicProps": false, "dynamicItems": false };
var SourceConnectionHealthReason = validate250;
function validate250(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate250.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate250.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CONFIGURATION_CHANGED" || data === "OBSERVED" || data === "SECRET_UNAVAILABLE" || data === "PROVIDER_UNAVAILABLE" || data === "PROVIDER_UNSUPPORTED" || data === "CREDENTIAL_REJECTED")) {
    validate250.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema86.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate250.errors = vErrors;
  return errors === 0;
}
validate250.evaluated = { "dynamicProps": false, "dynamicItems": false };
var SourceConnectionSpec = validate251;
function validate251(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate251.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.adapterId === void 0 && (missing0 = "adapterId") || data.endpointOrigin === void 0 && (missing0 = "endpointOrigin") || data.fetchCredentialRef === void 0 && (missing0 = "fetchCredentialRef") || data.reportCredentialRef === void 0 && (missing0 = "reportCredentialRef") || data.webhookSecretRef === void 0 && (missing0 = "webhookSecretRef")) {
        validate251.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "adapterId" || key0 === "endpointOrigin" || key0 === "fetchCredentialRef" || key0 === "reportCredentialRef" || key0 === "webhookSecretRef")) {
            validate251.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.adapterId !== void 0) {
            const _errs2 = errors;
            if (!validate57(data.adapterId, { instancePath: instancePath + "/adapterId", parentData: data, parentDataProperty: "adapterId", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.endpointOrigin !== void 0) {
              let data1 = data.endpointOrigin;
              const _errs3 = errors;
              const _errs5 = errors;
              const _errs6 = errors;
              if (typeof data1 === "string") {
                if (!pattern13.test(data1)) {
                  const err0 = {};
                  if (vErrors === null) {
                    vErrors = [err0];
                  } else {
                    vErrors.push(err0);
                  }
                  errors++;
                }
              }
              var valid1 = _errs6 === errors;
              if (valid1) {
                validate251.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/not", keyword: "not", params: {}, message: "must NOT be valid" }];
                return false;
              } else {
                errors = _errs5;
                if (vErrors !== null) {
                  if (_errs5) {
                    vErrors.length = _errs5;
                  } else {
                    vErrors = null;
                  }
                }
              }
              if (errors === _errs3) {
                if (errors === _errs3) {
                  if (typeof data1 === "string") {
                    if (func1(data1) > 512) {
                      validate251.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/maxLength", keyword: "maxLength", params: { limit: 512 }, message: "must NOT have more than 512 characters" }];
                      return false;
                    } else {
                      if (func1(data1) < 1) {
                        validate251.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
                        return false;
                      } else {
                        if (!pattern14.test(data1)) {
                          validate251.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/pattern", keyword: "pattern", params: { pattern: "^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$" }, message: 'must match pattern "^https://[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?$"' }];
                          return false;
                        } else {
                          if (!formats0(data1)) {
                            validate251.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/format", keyword: "format", params: { format: "uri" }, message: 'must match format "uri"' }];
                            return false;
                          }
                        }
                      }
                    }
                  } else {
                    validate251.errors = [{ instancePath: instancePath + "/endpointOrigin", schemaPath: "#/properties/endpointOrigin/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
                    return false;
                  }
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.fetchCredentialRef !== void 0) {
                const _errs7 = errors;
                if (!validate57(data.fetchCredentialRef, { instancePath: instancePath + "/fetchCredentialRef", parentData: data, parentDataProperty: "fetchCredentialRef", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                  errors = vErrors.length;
                }
                var valid0 = _errs7 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.reportCredentialRef !== void 0) {
                  const _errs8 = errors;
                  if (!validate57(data.reportCredentialRef, { instancePath: instancePath + "/reportCredentialRef", parentData: data, parentDataProperty: "reportCredentialRef", rootData, dynamicAnchors })) {
                    vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
                    errors = vErrors.length;
                  }
                  var valid0 = _errs8 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.webhookSecretRef !== void 0) {
                    const _errs9 = errors;
                    if (!validate57(data.webhookSecretRef, { instancePath: instancePath + "/webhookSecretRef", parentData: data, parentDataProperty: "webhookSecretRef", rootData, dynamicAnchors })) {
                      vErrors = vErrors === null ? validate57.errors : vErrors.concat(validate57.errors);
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
    } else {
      validate251.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate251.errors = vErrors;
  return errors === 0;
}
validate251.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var SourceConnectionStatus = validate256;
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
  const _errs1 = errors;
  const _errs2 = errors;
  let valid1 = true;
  const _errs3 = errors;
  if (data && typeof data == "object" && !Array.isArray(data)) {
    let missing0;
    if (data.health === void 0 && (missing0 = "health")) {
      const err0 = {};
      if (vErrors === null) {
        vErrors = [err0];
      } else {
        vErrors.push(err0);
      }
      errors++;
    } else {
      if (data.health !== void 0) {
        if ("PENDING" !== data.health) {
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
      let missing1;
      if (data.reason === void 0 && (missing1 = "reason")) {
        validate256.errors = [{ instancePath, schemaPath: "#/allOf/0/then/required", keyword: "required", params: { missingProperty: missing1 }, message: "must have required property '" + missing1 + "'" }];
        return false;
      } else {
        if (data.reason !== void 0) {
          if (!(data.reason === "CONFIGURATION_CHANGED")) {
            validate256.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/0/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema84.allOf[0].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
            return false;
          }
        }
      }
    }
    var _valid0 = _errs5 === errors;
    valid1 = _valid0;
    if (valid1) {
      var props0 = {};
      props0.reason = true;
      props0.health = true;
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
    validate256.errors = vErrors;
    return false;
  }
  var valid0 = _errs1 === errors;
  if (valid0) {
    const _errs7 = errors;
    const _errs8 = errors;
    let valid4 = true;
    const _errs9 = errors;
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing2;
      if (data.health === void 0 && (missing2 = "health")) {
        const err3 = {};
        if (vErrors === null) {
          vErrors = [err3];
        } else {
          vErrors.push(err3);
        }
        errors++;
      } else {
        if (data.health !== void 0) {
          if ("READY" !== data.health) {
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
        let missing3;
        if (data.reason === void 0 && (missing3 = "reason")) {
          validate256.errors = [{ instancePath, schemaPath: "#/allOf/1/then/required", keyword: "required", params: { missingProperty: missing3 }, message: "must have required property '" + missing3 + "'" }];
          return false;
        } else {
          if (data.reason !== void 0) {
            if (!(data.reason === "OBSERVED")) {
              validate256.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/1/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema84.allOf[1].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
              return false;
            }
          }
        }
      }
      var _valid1 = _errs11 === errors;
      valid4 = _valid1;
      if (valid4) {
        var props1 = {};
        props1.reason = true;
        props1.health = true;
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
      validate256.errors = vErrors;
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
      const _errs13 = errors;
      const _errs14 = errors;
      let valid7 = true;
      const _errs15 = errors;
      if (data && typeof data == "object" && !Array.isArray(data)) {
        let missing4;
        if (data.health === void 0 && (missing4 = "health")) {
          const err6 = {};
          if (vErrors === null) {
            vErrors = [err6];
          } else {
            vErrors.push(err6);
          }
          errors++;
        } else {
          if (data.health !== void 0) {
            if ("UNAVAILABLE" !== data.health) {
              const err7 = {};
              if (vErrors === null) {
                vErrors = [err7];
              } else {
                vErrors.push(err7);
              }
              errors++;
            }
          }
        }
      }
      var _valid2 = _errs15 === errors;
      errors = _errs14;
      if (vErrors !== null) {
        if (_errs14) {
          vErrors.length = _errs14;
        } else {
          vErrors = null;
        }
      }
      if (_valid2) {
        const _errs17 = errors;
        if (data && typeof data == "object" && !Array.isArray(data)) {
          let missing5;
          if (data.reason === void 0 && (missing5 = "reason")) {
            validate256.errors = [{ instancePath, schemaPath: "#/allOf/2/then/required", keyword: "required", params: { missingProperty: missing5 }, message: "must have required property '" + missing5 + "'" }];
            return false;
          } else {
            if (data.reason !== void 0) {
              let data5 = data.reason;
              if (!(data5 === "SECRET_UNAVAILABLE" || data5 === "PROVIDER_UNAVAILABLE" || data5 === "PROVIDER_UNSUPPORTED" || data5 === "CREDENTIAL_REJECTED")) {
                validate256.errors = [{ instancePath: instancePath + "/reason", schemaPath: "#/allOf/2/then/properties/reason/enum", keyword: "enum", params: { allowedValues: schema84.allOf[2].then.properties.reason.enum }, message: "must be equal to one of the allowed values" }];
                return false;
              }
            }
          }
        }
        var _valid2 = _errs17 === errors;
        valid7 = _valid2;
        if (valid7) {
          var props2 = {};
          props2.reason = true;
          props2.health = true;
        }
      }
      if (!valid7) {
        const err8 = { instancePath, schemaPath: "#/allOf/2/if", keyword: "if", params: { failingKeyword: "then" }, message: 'must match "then" schema' };
        if (vErrors === null) {
          vErrors = [err8];
        } else {
          vErrors.push(err8);
        }
        errors++;
        validate256.errors = vErrors;
        return false;
      }
      var valid0 = _errs13 === errors;
      if (valid0) {
        if (props0 !== true && props2 !== void 0) {
          if (props2 === true) {
            props0 = true;
          } else {
            props0 = props0 || {};
            Object.assign(props0, props2);
          }
        }
      }
    }
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing6;
      if (data.health === void 0 && (missing6 = "health") || data.observedAt === void 0 && (missing6 = "observedAt") || data.reason === void 0 && (missing6 = "reason")) {
        validate256.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing6 }, message: "must have required property '" + missing6 + "'" }];
        return false;
      } else {
        const _errs19 = errors;
        for (const key0 in data) {
          if (!(key0 === "health" || key0 === "observedAt" || key0 === "reason")) {
            validate256.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs19 === errors) {
          if (data.health !== void 0) {
            const _errs20 = errors;
            if (!validate243(data.health, { instancePath: instancePath + "/health", parentData: data, parentDataProperty: "health", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate243.errors : vErrors.concat(validate243.errors);
              errors = vErrors.length;
            }
            var valid10 = _errs20 === errors;
          } else {
            var valid10 = true;
          }
          if (valid10) {
            if (data.observedAt !== void 0) {
              const _errs21 = errors;
              if (!validate91(data.observedAt, { instancePath: instancePath + "/observedAt", parentData: data, parentDataProperty: "observedAt", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate91.errors : vErrors.concat(validate91.errors);
                errors = vErrors.length;
              }
              var valid10 = _errs21 === errors;
            } else {
              var valid10 = true;
            }
            if (valid10) {
              if (data.reason !== void 0) {
                const _errs22 = errors;
                if (!validate246(data.reason, { instancePath: instancePath + "/reason", parentData: data, parentDataProperty: "reason", rootData, dynamicAnchors })) {
                  vErrors = vErrors === null ? validate246.errors : vErrors.concat(validate246.errors);
                  errors = vErrors.length;
                }
                var valid10 = _errs22 === errors;
              } else {
                var valid10 = true;
              }
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
var SubjectKind = validate260;
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
  if (typeof data !== "string") {
    validate260.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "USER" || data === "SERVICE_ACCOUNT")) {
    validate260.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema46.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate260.errors = vErrors;
  return errors === 0;
}
validate260.evaluated = { "dynamicProps": false, "dynamicItems": false };
var SubjectRef = validate261;
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
      if (data.id === void 0 && (missing0 = "id") || data.kind === void 0 && (missing0 = "kind")) {
        validate261.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "id" || key0 === "kind")) {
            validate261.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.id !== void 0) {
            const _errs2 = errors;
            if (typeof data.id !== "string") {
              validate261.errors = [{ instancePath: instancePath + "/id", schemaPath: "#/properties/id/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.kind !== void 0) {
              const _errs4 = errors;
              if (!validate114(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
                vErrors = vErrors === null ? validate114.errors : vErrors.concat(validate114.errors);
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
      validate261.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate261.errors = vErrors;
  return errors === 0;
}
validate261.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var TenantID = validate263;
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
    if (typeof data === "string") {
      if (func1(data) > 128) {
        validate263.errors = [{ instancePath, schemaPath: "#/maxLength", keyword: "maxLength", params: { limit: 128 }, message: "must NOT have more than 128 characters" }];
        return false;
      } else {
        if (func1(data) < 1) {
          validate263.errors = [{ instancePath, schemaPath: "#/minLength", keyword: "minLength", params: { limit: 1 }, message: "must NOT have fewer than 1 characters" }];
          return false;
        } else {
          if (!pattern5.test(data)) {
            validate263.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }, message: 'must match pattern "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"' }];
            return false;
          }
        }
      }
    } else {
      validate263.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
      return false;
    }
  }
  validate263.errors = vErrors;
  return errors === 0;
}
validate263.evaluated = { "dynamicProps": false, "dynamicItems": false };
var Timestamp = validate264;
function validate264(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate264.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (errors === 0) {
      if (typeof data === "string") {
        if (!pattern15.test(data)) {
          validate264.errors = [{ instancePath, schemaPath: "#/pattern", keyword: "pattern", params: { pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$" }, message: 'must match pattern "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,6})?Z$"' }];
          return false;
        } else {
          if (!formats2.validate(data)) {
            validate264.errors = [{ instancePath, schemaPath: "#/format", keyword: "format", params: { format: "date-time" }, message: 'must match format "date-time"' }];
            return false;
          }
        }
      } else {
        validate264.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
        return false;
      }
    }
  }
  validate264.errors = vErrors;
  return errors === 0;
}
validate264.evaluated = { "dynamicProps": false, "dynamicItems": false };
var TriggerPolicy = validate265;
function validate265(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate265.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate265.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "CHANGE")) {
    validate265.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema28.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate265.errors = vErrors;
  return errors === 0;
}
validate265.evaluated = { "dynamicProps": false, "dynamicItems": false };
var UpdatePipelineDraftRequest = validate266;
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
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.draft === void 0 && (missing0 = "draft")) {
        validate266.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "draft")) {
            validate266.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.draft !== void 0) {
            if (!validate60(data.draft, { instancePath: instancePath + "/draft", parentData: data, parentDataProperty: "draft", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate60.errors : vErrors.concat(validate60.errors);
              errors = vErrors.length;
            }
          }
        }
      }
    } else {
      validate266.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate266.errors = vErrors;
  return errors === 0;
}
validate266.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var VerificationLimits = validate268;
function validate268(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate268.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.cpuMillis === void 0 && (missing0 = "cpuMillis") || data.maxLogBytes === void 0 && (missing0 = "maxLogBytes") || data.memoryBytes === void 0 && (missing0 = "memoryBytes") || data.processLimit === void 0 && (missing0 = "processLimit") || data.runTimeoutSeconds === void 0 && (missing0 = "runTimeoutSeconds") || data.stepTimeoutSeconds === void 0 && (missing0 = "stepTimeoutSeconds") || data.writableBytes === void 0 && (missing0 = "writableBytes")) {
        validate268.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "cpuMillis" || key0 === "maxLogBytes" || key0 === "memoryBytes" || key0 === "processLimit" || key0 === "runTimeoutSeconds" || key0 === "stepTimeoutSeconds" || key0 === "writableBytes")) {
            validate268.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.cpuMillis !== void 0) {
            const _errs2 = errors;
            if (2e3 !== data.cpuMillis) {
              validate268.errors = [{ instancePath: instancePath + "/cpuMillis", schemaPath: "#/properties/cpuMillis/const", keyword: "const", params: { allowedValue: 2e3 }, message: "must be equal to constant" }];
              return false;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.maxLogBytes !== void 0) {
              const _errs3 = errors;
              if (8388608 !== data.maxLogBytes) {
                validate268.errors = [{ instancePath: instancePath + "/maxLogBytes", schemaPath: "#/properties/maxLogBytes/const", keyword: "const", params: { allowedValue: 8388608 }, message: "must be equal to constant" }];
                return false;
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
            if (valid0) {
              if (data.memoryBytes !== void 0) {
                const _errs4 = errors;
                if (2147483648 !== data.memoryBytes) {
                  validate268.errors = [{ instancePath: instancePath + "/memoryBytes", schemaPath: "#/properties/memoryBytes/const", keyword: "const", params: { allowedValue: 2147483648 }, message: "must be equal to constant" }];
                  return false;
                }
                var valid0 = _errs4 === errors;
              } else {
                var valid0 = true;
              }
              if (valid0) {
                if (data.processLimit !== void 0) {
                  const _errs5 = errors;
                  if (256 !== data.processLimit) {
                    validate268.errors = [{ instancePath: instancePath + "/processLimit", schemaPath: "#/properties/processLimit/const", keyword: "const", params: { allowedValue: 256 }, message: "must be equal to constant" }];
                    return false;
                  }
                  var valid0 = _errs5 === errors;
                } else {
                  var valid0 = true;
                }
                if (valid0) {
                  if (data.runTimeoutSeconds !== void 0) {
                    const _errs6 = errors;
                    if (1200 !== data.runTimeoutSeconds) {
                      validate268.errors = [{ instancePath: instancePath + "/runTimeoutSeconds", schemaPath: "#/properties/runTimeoutSeconds/const", keyword: "const", params: { allowedValue: 1200 }, message: "must be equal to constant" }];
                      return false;
                    }
                    var valid0 = _errs6 === errors;
                  } else {
                    var valid0 = true;
                  }
                  if (valid0) {
                    if (data.stepTimeoutSeconds !== void 0) {
                      const _errs7 = errors;
                      if (600 !== data.stepTimeoutSeconds) {
                        validate268.errors = [{ instancePath: instancePath + "/stepTimeoutSeconds", schemaPath: "#/properties/stepTimeoutSeconds/const", keyword: "const", params: { allowedValue: 600 }, message: "must be equal to constant" }];
                        return false;
                      }
                      var valid0 = _errs7 === errors;
                    } else {
                      var valid0 = true;
                    }
                    if (valid0) {
                      if (data.writableBytes !== void 0) {
                        const _errs8 = errors;
                        if (2147483648 !== data.writableBytes) {
                          validate268.errors = [{ instancePath: instancePath + "/writableBytes", schemaPath: "#/properties/writableBytes/const", keyword: "const", params: { allowedValue: 2147483648 }, message: "must be equal to constant" }];
                          return false;
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
      }
    } else {
      validate268.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate268.errors = vErrors;
  return errors === 0;
}
validate268.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var VerificationProfile = validate269;
function validate269(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate269.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate269.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "GO_1_26_OFFLINE_V1")) {
    validate269.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema29.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate269.errors = vErrors;
  return errors === 0;
}
validate269.evaluated = { "dynamicProps": false, "dynamicItems": false };
var VerificationStep = validate270;
function validate270(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate270.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (errors === 0) {
    if (data && typeof data == "object" && !Array.isArray(data)) {
      let missing0;
      if (data.kind === void 0 && (missing0 = "kind") || data.ordinal === void 0 && (missing0 = "ordinal")) {
        validate270.errors = [{ instancePath, schemaPath: "#/required", keyword: "required", params: { missingProperty: missing0 }, message: "must have required property '" + missing0 + "'" }];
        return false;
      } else {
        const _errs1 = errors;
        for (const key0 in data) {
          if (!(key0 === "kind" || key0 === "ordinal")) {
            validate270.errors = [{ instancePath, schemaPath: "#/additionalProperties", keyword: "additionalProperties", params: { additionalProperty: key0 }, message: "must NOT have additional properties" }];
            return false;
            break;
          }
        }
        if (_errs1 === errors) {
          if (data.kind !== void 0) {
            const _errs2 = errors;
            if (!validate191(data.kind, { instancePath: instancePath + "/kind", parentData: data, parentDataProperty: "kind", rootData, dynamicAnchors })) {
              vErrors = vErrors === null ? validate191.errors : vErrors.concat(validate191.errors);
              errors = vErrors.length;
            }
            var valid0 = _errs2 === errors;
          } else {
            var valid0 = true;
          }
          if (valid0) {
            if (data.ordinal !== void 0) {
              let data1 = data.ordinal;
              const _errs3 = errors;
              if (!(typeof data1 == "number" && (!(data1 % 1) && !isNaN(data1)))) {
                validate270.errors = [{ instancePath: instancePath + "/ordinal", schemaPath: "#/properties/ordinal/type", keyword: "type", params: { type: "integer" }, message: "must be integer" }];
                return false;
              }
              if (errors === _errs3) {
                if (typeof data1 == "number") {
                  if (data1 > 2 || isNaN(data1)) {
                    validate270.errors = [{ instancePath: instancePath + "/ordinal", schemaPath: "#/properties/ordinal/maximum", keyword: "maximum", params: { comparison: "<=", limit: 2 }, message: "must be <= 2" }];
                    return false;
                  } else {
                    if (data1 < 1 || isNaN(data1)) {
                      validate270.errors = [{ instancePath: instancePath + "/ordinal", schemaPath: "#/properties/ordinal/minimum", keyword: "minimum", params: { comparison: ">=", limit: 1 }, message: "must be >= 1" }];
                      return false;
                    }
                  }
                }
              }
              var valid0 = _errs3 === errors;
            } else {
              var valid0 = true;
            }
          }
        }
      }
    } else {
      validate270.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "object" }, message: "must be object" }];
      return false;
    }
  }
  validate270.errors = vErrors;
  return errors === 0;
}
validate270.evaluated = { "props": true, "dynamicProps": false, "dynamicItems": false };
var VerificationStepKind = validate272;
function validate272(data, { instancePath = "", parentData, parentDataProperty, rootData = data, dynamicAnchors = {} } = {}) {
  let vErrors = null;
  let errors = 0;
  const evaluated0 = validate272.evaluated;
  if (evaluated0.dynamicProps) {
    evaluated0.props = void 0;
  }
  if (evaluated0.dynamicItems) {
    evaluated0.items = void 0;
  }
  if (typeof data !== "string") {
    validate272.errors = [{ instancePath, schemaPath: "#/type", keyword: "type", params: { type: "string" }, message: "must be string" }];
    return false;
  }
  if (!(data === "GO_TEST" || data === "GO_VET")) {
    validate272.errors = [{ instancePath, schemaPath: "#/enum", keyword: "enum", params: { allowedValues: schema64.enum }, message: "must be equal to one of the allowed values" }];
    return false;
  }
  validate272.errors = vErrors;
  return errors === 0;
}
validate272.evaluated = { "dynamicProps": false, "dynamicItems": false };
export {
  ChangeAction,
  ChangeIdentity,
  CreateDevOpsProjectRequest,
  CreatePipelineRequest,
  CreateRepositoryBindingRequest,
  CreateSourceConnectionRequest,
  DependencyEgressPolicy,
  DevOpsProject,
  Pipeline,
  PipelineActivation,
  PipelineDraft,
  PipelineDraftSpec,
  PipelineRevision,
  PipelineRevisionReference,
  PipelineRevisionSpec,
  PipelineRun,
  PipelineRunInput,
  PipelineRunLogChunk,
  PipelineRunLogPage,
  PipelineRunReason,
  PipelineRunReplay,
  PipelineRunStage,
  PipelineRunState,
  PipelineRunStatus,
  ReporterPolicy,
  RepositoryBinding,
  RepositoryBindingHealth,
  RepositoryBindingHealthReason,
  RepositoryBindingSpec,
  RepositoryBindingStatus,
  ResourceID,
  ResourceMetadata,
  ResourceScope,
  SourceConnection,
  SourceConnectionHealth,
  SourceConnectionHealthReason,
  SourceConnectionSpec,
  SourceConnectionStatus,
  SubjectKind,
  SubjectRef,
  TenantID,
  Timestamp,
  TriggerPolicy,
  UpdatePipelineDraftRequest,
  VerificationLimits,
  VerificationProfile,
  VerificationStep,
  VerificationStepKind
};
