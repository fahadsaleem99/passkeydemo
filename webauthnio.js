/* [@simplewebauthn/browser@6.2.1] */
!function(e, t) {
    "object" == typeof exports && "undefined" != typeof module ? t(exports) : "function" == typeof define && define.amd ? define(["exports"], t) : t((e = "undefined" != typeof globalThis ? globalThis : e || self).SimpleWebAuthnBrowser = {})
}(this, (function(e) {
    "use strict";
    var t = function(e, r) {
        return t = Object.setPrototypeOf || {
            __proto__: []
        }instanceof Array && function(e, t) {
            e.__proto__ = t
        }
        || function(e, t) {
            for (var r in t)
                Object.prototype.hasOwnProperty.call(t, r) && (e[r] = t[r])
        }
        ,
        t(e, r)
    };
    var r = function() {
        return r = Object.assign || function(e) {
            for (var t, r = 1, n = arguments.length; r < n; r++)
                for (var o in t = arguments[r])
                    Object.prototype.hasOwnProperty.call(t, o) && (e[o] = t[o]);
            return e
        }
        ,
        r.apply(this, arguments)
    };
    function n(e, t, r, n) {
        return new (r || (r = Promise))((function(o, i) {
            function a(e) {
                try {
                    u(n.next(e))
                } catch (e) {
                    i(e)
                }
            }
            function l(e) {
                try {
                    u(n.throw(e))
                } catch (e) {
                    i(e)
                }
            }
            function u(e) {
                var t;
                e.done ? o(e.value) : (t = e.value,
                t instanceof r ? t : new r((function(e) {
                    e(t)
                }
                ))).then(a, l)
            }
            u((n = n.apply(e, t || [])).next())
        }
        ))
    }
    function o(e, t) {
        var r, n, o, i, a = {
            label: 0,
            sent: function() {
                if (1 & o[0])
                    throw o[1];
                return o[1]
            },
            trys: [],
            ops: []
        };
        return i = {
            next: l(0),
            throw: l(1),
            return: l(2)
        },
        "function" == typeof Symbol && (i[Symbol.iterator] = function() {
            return this
        }
        ),
        i;
        function l(i) {
            return function(l) {
                return function(i) {
                    if (r)
                        throw new TypeError("Generator is already executing.");
                    for (; a; )
                        try {
                            if (r = 1,
                            n && (o = 2 & i[0] ? n.return : i[0] ? n.throw || ((o = n.return) && o.call(n),
                            0) : n.next) && !(o = o.call(n, i[1])).done)
                                return o;
                            switch (n = 0,
                            o && (i = [2 & i[0], o.value]),
                            i[0]) {
                            case 0:
                            case 1:
                                o = i;
                                break;
                            case 4:
                                return a.label++,
                                {
                                    value: i[1],
                                    done: !1
                                };
                            case 5:
                                a.label++,
                                n = i[1],
                                i = [0];
                                continue;
                            case 7:
                                i = a.ops.pop(),
                                a.trys.pop();
                                continue;
                            default:
                                if (!(o = a.trys,
                                (o = o.length > 0 && o[o.length - 1]) || 6 !== i[0] && 2 !== i[0])) {
                                    a = 0;
                                    continue
                                }
                                if (3 === i[0] && (!o || i[1] > o[0] && i[1] < o[3])) {
                                    a.label = i[1];
                                    break
                                }
                                if (6 === i[0] && a.label < o[1]) {
                                    a.label = o[1],
                                    o = i;
                                    break
                                }
                                if (o && a.label < o[2]) {
                                    a.label = o[2],
                                    a.ops.push(i);
                                    break
                                }
                                o[2] && a.ops.pop(),
                                a.trys.pop();
                                continue
                            }
                            i = t.call(e, a)
                        } catch (e) {
                            i = [6, e],
                            n = 0
                        } finally {
                            r = o = 0
                        }
                    if (5 & i[0])
                        throw i[1];
                    return {
                        value: i[0] ? i[1] : void 0,
                        done: !0
                    }
                }([i, l])
            }
        }
    }
    function i(e) {
        var t, r, n = new Uint8Array(e), o = "";
        try {
            for (var i = function(e) {
                var t = "function" == typeof Symbol && Symbol.iterator
                  , r = t && e[t]
                  , n = 0;
                if (r)
                    return r.call(e);
                if (e && "number" == typeof e.length)
                    return {
                        next: function() {
                            return e && n >= e.length && (e = void 0),
                            {
                                value: e && e[n++],
                                done: !e
                            }
                        }
                    };
                throw new TypeError(t ? "Object is not iterable." : "Symbol.iterator is not defined.")
            }(n), a = i.next(); !a.done; a = i.next()) {
                var l = a.value;
                o += String.fromCharCode(l)
            }
        } catch (e) {
            t = {
                error: e
            }
        } finally {
            try {
                a && !a.done && (r = i.return) && r.call(i)
            } finally {
                if (t)
                    throw t.error
            }
        }
        return btoa(o).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
    }
    function a(e) {
        for (var t = e.replace(/-/g, "+").replace(/_/g, "/"), r = (4 - t.length % 4) % 4, n = t.padEnd(t.length + r, "="), o = atob(n), i = new ArrayBuffer(o.length), a = new Uint8Array(i), l = 0; l < o.length; l++)
            a[l] = o.charCodeAt(l);
        return i
    }
    function l() {
        return void 0 !== (null === window || void 0 === window ? void 0 : window.PublicKeyCredential) && "function" == typeof window.PublicKeyCredential
    }
    function u(e) {
        var t = e.id;
        return r(r({}, e), {
            id: a(t),
            transports: e.transports
        })
    }
    function s(e) {
        return "localhost" === e || /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(e)
    }
    var c = function(e) {
        function r(t, r) {
            void 0 === r && (r = "WebAuthnError");
            var n = e.call(this, t) || this;
            return n.name = r,
            n
        }
        return function(e, r) {
            if ("function" != typeof r && null !== r)
                throw new TypeError("Class extends value " + String(r) + " is not a constructor or null");
            function n() {
                this.constructor = e
            }
            t(e, r),
            e.prototype = null === r ? Object.create(r) : (n.prototype = r.prototype,
            new n)
        }(r, e),
        r
    }(Error);
    var d = new (function() {
        function e() {}
        return e.prototype.createNewAbortSignal = function() {
            return this.controller && this.controller.abort("Cancelling existing WebAuthn API call for new one"),
            this.controller = new AbortController,
            this.controller.signal
        }
        ,
        e
    }());
    function f() {
        return n(this, void 0, void 0, (function() {
            var e;
            return o(this, (function(t) {
                return navigator.credentials.conditionalMediationSupported ? [2, !0] : [2, void 0 !== (e = window.PublicKeyCredential).isConditionalMediationAvailable && e.isConditionalMediationAvailable()]
            }
            ))
        }
        ))
    }
    e.browserSupportsWebAuthn = l,
    e.browserSupportsWebAuthnAutofill = f,
    e.platformAuthenticatorIsAvailable = function() {
        return n(this, void 0, void 0, (function() {
            return o(this, (function(e) {
                return l() ? [2, PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()] : [2, !1]
            }
            ))
        }
        ))
    }
    ,
    e.startAuthentication = function(e, t) {
        var p, h;
        return void 0 === t && (t = !1),
        n(this, void 0, void 0, (function() {
            var n, w, b, y, v, g, m, E, A;
            return o(this, (function(o) {
                switch (o.label) {
                case 0:
                    if (!l())
                        throw new Error("WebAuthn is not supported in this browser");
                    return 0 !== (null === (p = e.allowCredentials) || void 0 === p ? void 0 : p.length) && (n = null === (h = e.allowCredentials) || void 0 === h ? void 0 : h.map(u)),
                    w = r(r({}, e), {
                        challenge: a(e.challenge),
                        allowCredentials: n
                    }),
                    b = {},
                    t ? [4, f()] : [3, 2];
                case 1:
                    if (!o.sent())
                        throw Error("Browser does not support WebAuthn autofill");
                    if (document.querySelectorAll("input[autocomplete*='webauthn']").length < 1)
                        throw Error('No <input> with `"webauthn"` in its `autocomplete` attribute was detected');
                    b.mediation = "conditional",
                    w.allowCredentials = [],
                    o.label = 2;
                case 2:
                    b.publicKey = w,
                    b.signal = d.createNewAbortSignal(),
                    o.label = 3;
                case 3:
                    return o.trys.push([3, 5, , 6]),
                    [4, navigator.credentials.get(b)];
                case 4:
                    return y = o.sent(),
                    [3, 6];
                case 5:
                    throw function(e) {
                        var t, r = e.error, n = e.options, o = n.publicKey;
                        if (!o)
                            throw Error("options was missing required publicKey property");
                        if ("AbortError" === r.name) {
                            if (n.signal === (new AbortController).signal)
                                return new c("Authentication ceremony was sent an abort signal","AbortError")
                        } else {
                            if ("NotAllowedError" === r.name)
                                return (null === (t = o.allowCredentials) || void 0 === t ? void 0 : t.length) ? new c("No available authenticator recognized any of the allowed credentials","NotAllowedError") : new c("User clicked cancel, or the authentication ceremony timed out","NotAllowedError");
                            if ("SecurityError" === r.name) {
                                var i = window.location.hostname;
                                if (!s(i))
                                    return new c("".concat(window.location.hostname, " is an invalid domain"),"SecurityError");
                                if (o.rpId !== i)
                                    return new c('The RP ID "'.concat(o.rpId, '" is invalid for this domain'),"SecurityError")
                            } else if ("UnknownError" === r.name)
                                return new c("The authenticator was unable to process the specified options, or could not create a new assertion signature","UnknownError")
                        }
                        return r
                    }({
                        error: o.sent(),
                        options: b
                    });
                case 6:
                    if (!y)
                        throw new Error("Authentication was not completed");
                    return v = y.id,
                    g = y.rawId,
                    m = y.response,
                    E = y.type,
                    A = void 0,
                    m.userHandle && (S = m.userHandle,
                    A = new TextDecoder("utf-8").decode(S)),
                    [2, {
                        id: v,
                        rawId: i(g),
                        response: {
                            authenticatorData: i(m.authenticatorData),
                            clientDataJSON: i(m.clientDataJSON),
                            signature: i(m.signature),
                            userHandle: A
                        },
                        type: E,
                        clientExtensionResults: y.getClientExtensionResults(),
                        authenticatorAttachment: y.authenticatorAttachment
                    }]
                }
                var S
            }
            ))
        }
        ))
    }
    ,
    e.startRegistration = function(e) {
        return n(this, void 0, void 0, (function() {
            var t, n, f, p, h, w, b, y;
            return o(this, (function(o) {
                switch (o.label) {
                case 0:
                    if (!l())
                        throw new Error("WebAuthn is not supported in this browser");
                    t = r(r({}, e), {
                        challenge: a(e.challenge),
                        user: r(r({}, e.user), {
                            id: (v = e.user.id,
                            (new TextEncoder).encode(v))
                        }),
                        excludeCredentials: e.excludeCredentials.map(u)
                    }),
                    (n = {
                        publicKey: t
                    }).signal = d.createNewAbortSignal(),
                    o.label = 1;
                case 1:
                    return o.trys.push([1, 3, , 4]),
                    [4, navigator.credentials.create(n)];
                case 2:
                    return f = o.sent(),
                    [3, 4];
                case 3:
                    throw function(e) {
                        var t, r, n = e.error, o = e.options, i = o.publicKey;
                        if (!i)
                            throw Error("options was missing required publicKey property");
                        if ("AbortError" === n.name) {
                            if (o.signal === (new AbortController).signal)
                                return new c("Registration ceremony was sent an abort signal","AbortError")
                        } else if ("ConstraintError" === n.name) {
                            if (!0 === (null === (t = i.authenticatorSelection) || void 0 === t ? void 0 : t.requireResidentKey))
                                return new c("Discoverable credentials were required but no available authenticator supported it","ConstraintError");
                            if ("required" === (null === (r = i.authenticatorSelection) || void 0 === r ? void 0 : r.userVerification))
                                return new c("User verification was required but no available authenticator supported it","ConstraintError")
                        } else {
                            if ("InvalidStateError" === n.name)
                                return new c("The authenticator was previously registered","InvalidStateError");
                            if ("NotAllowedError" === n.name)
                                return new c("User clicked cancel, or the registration ceremony timed out","NotAllowedError");
                            if ("NotSupportedError" === n.name)
                                return 0 === i.pubKeyCredParams.filter((function(e) {
                                    return "public-key" === e.type
                                }
                                )).length ? new c('No entry in pubKeyCredParams was of type "public-key"',"NotSupportedError") : new c("No available authenticator supported any of the specified pubKeyCredParams algorithms","NotSupportedError");
                            if ("SecurityError" === n.name) {
                                var a = window.location.hostname;
                                if (!s(a))
                                    return new c("".concat(window.location.hostname, " is an invalid domain"),"SecurityError");
                                if (i.rp.id !== a)
                                    return new c('The RP ID "'.concat(i.rp.id, '" is invalid for this domain'),"SecurityError")
                            } else if ("TypeError" === n.name) {
                                if (i.user.id.byteLength < 1 || i.user.id.byteLength > 64)
                                    return new c("User ID was not between 1 and 64 characters","TypeError")
                            } else if ("UnknownError" === n.name)
                                return new c("The authenticator was unable to process the specified options, or could not create a new credential","UnknownError")
                        }
                        return n
                    }({
                        error: o.sent(),
                        options: n
                    });
                case 4:
                    if (!f)
                        throw new Error("Registration was not completed");
                    return p = f.id,
                    h = f.rawId,
                    w = f.response,
                    b = f.type,
                    y = {
                        id: p,
                        rawId: i(h),
                        response: {
                            attestationObject: i(w.attestationObject),
                            clientDataJSON: i(w.clientDataJSON)
                        },
                        type: b,
                        clientExtensionResults: f.getClientExtensionResults(),
                        authenticatorAttachment: f.authenticatorAttachment
                    },
                    "function" == typeof w.getTransports && (y.transports = w.getTransports()),
                    [2, y]
                }
                var v
            }
            ))
        }
        ))
    }
    ,
    Object.defineProperty(e, "__esModule", {
        value: !0
    })
}
));
