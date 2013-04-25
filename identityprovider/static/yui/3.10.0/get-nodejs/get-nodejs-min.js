/*
YUI 3.10.0 (build a03ce0e)
Copyright 2013 Yahoo! Inc. All rights reserved.
Licensed under the BSD License.
http://yuilibrary.com/license/
*/

YUI.add("get",function(e,t){var n=require("module"),r=require("path"),i=require("fs"),s=require("request"),o=function(t,n,r){e.Lang.isFunction(t.onEnd)&&t.onEnd.call(e,n,r)},u=function(t){e.Lang.isFunction(t.onSuccess)&&t.onSuccess.call(e,t),o(t,"success","success")},a=function(t,n){n.errors=[n],e.Lang.isFunction(t.onFailure)&&t.onFailure.call(e,n,t),o(t,n,"fail")};e.Get=function(){},e.config.base=r.join(__dirname,"../"),YUI.require=require,YUI.process=process,e.Get._exec=function(e,t,i){e.charCodeAt(0)===65279&&(e=e.slice(1));var s=new n(t,module);s.filename=t,s.paths=n._nodeModulePaths(r.dirname(t)),typeof YUI._getLoadHook=="function"&&(e=YUI._getLoadHook(e,t)),s._compile("module.exports = function (YUI) {"+e+"\n;return YUI;};",t),YUI=s.exports(YUI),s.loaded=!0,i(null,t)},e.Get._include=function(t,r){var o,u,a=this;if(t.match(/^https?:\/\//))o={url:t,timeout:a.timeout},s(o,function(n,i,s){n?r(n,t):e.Get._exec(s,t,r)});else{try{t=n._findPath(t,n._resolveLookupPaths(t,module.parent.parent)[1]);if(!e.config.useSync){i.readFile(t,"utf8",function(n,i){n?r(n,t):e.Get._exec(i,t,r)});return}u=i.readFileSync(t,"utf8")}catch(f){r(f,t);return}e.Get._exec(u,t,r)}},e.Get.js=function(t,n){var r=e.Array(t),i,s,o=r.length,f=0,l=function(){f===o&&u(n)};for(s=0;s<o;s++)i=r[s],e.Lang.isObject(i)&&(i=i.url),i=i.replace(/'/g,"%27"),e.Get._include(i,function(t,r){e.config||(e.config={debug:!0}),n.onProgress&&n.onProgress.call(n.context||e,r),t?a(n,t):(f++,l())});return{execute:function(){}}},e.Get.script=e.Get.js,e.Get.css=function(e,t){u(t)}},"@VERSION@");
