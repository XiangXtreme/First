// ==UserScript==
// @name         Bypass_Debugger
// @namespace    https://github.com/0xsdeo/Bypass_Debugger
// @version      2024-12-06
// @description  Bypass new Function --> debugger && constructor --> debugger && eval --> debugger
// @author       0xsdeo
// @match        http://*/*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        none
// @run-at       document-start
// ==/UserScript==

(function() {
    'use strict';

    globalThis.__INJECTED__ = true;

    // eval may not exist in WeChat miniapp context
    if (typeof eval !== 'undefined') {
        try {
            let temp_eval = eval;
            window.eval = function () {
                if (typeof arguments[0] == "string") {
                    arguments[0] = arguments[0].replaceAll(/debugger/g, '');
                }
                return temp_eval(...arguments);
            }
        } catch(e) {}
    }

    try {
        let OrigFunction = Function;

        let NewFunction = function () {
            for (let i = 0; i < arguments.length; i++) {
                if (typeof arguments[i] == "string") {
                    arguments[i] = arguments[i].replaceAll(/debugger/g, '');
                }
            }
            return OrigFunction(...arguments);
        }

        // Try to set prototype, skip if read-only (WeChat freezes Function)
        try { NewFunction.prototype = OrigFunction.prototype; } catch(e) {}
        try {
            NewFunction.prototype.constructor = function () {
                for (let i = 0; i < arguments.length; i++) {
                    if (typeof arguments[i] == "string") {
                        arguments[i] = arguments[i].replaceAll(/debugger/g, '');
                    }
                }
                return OrigFunction(...arguments);
            }
            NewFunction.prototype.constructor.prototype = NewFunction.prototype;
        } catch(e) {}

        // Replace global Function
        try { window.Function = NewFunction; } catch(e) {}
        try { globalThis.Function = NewFunction; } catch(e) {}
        try { Object.freeze(NewFunction); } catch(e) {}
    } catch(e) {}

    // Also patch setTimeout/setInterval which can take string arguments with debugger
    try {
        let origSetTimeout = setTimeout;
        window.setTimeout = function(fn, delay) {
            if (typeof fn === 'string') {
                fn = fn.replaceAll(/debugger/g, '');
            }
            return origSetTimeout.apply(this, arguments);
        };
    } catch(e) {}

    try {
        let origSetInterval = setInterval;
        window.setInterval = function(fn, delay) {
            if (typeof fn === 'string') {
                fn = fn.replaceAll(/debugger/g, '');
            }
            return origSetInterval.apply(this, arguments);
        };
    } catch(e) {}

    console.log('[Bypass_Debugger] hooks installed');
    window.__BYPASS_DEBUGGER__ = true;
    Object.freeze(Function);
})();
