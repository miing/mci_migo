/*
YUI 3.10.0 (build a03ce0e)
Copyright 2013 Yahoo! Inc. All rights reserved.
Licensed under the BSD License.
http://yuilibrary.com/license/
*/

YUI.add("base-core",function(e,t){function v(e){this._BaseInvoked||(this._BaseInvoked=!0,this._initBase(e))}var n=e.Object,r=e.Lang,i=".",s="initialized",o="destroyed",u="initializer",a="value",f=Object.prototype.constructor,l="deep",c="shallow",h="destructor",p=e.AttributeCore,d=function(e,t,n){var r;for(r in t)n[r]&&(e[r]=t[r]);return e};v._ATTR_CFG=p._ATTR_CFG.concat("cloneDefaultValue"),v._NON_ATTRS_CFG=["plugins"],v.NAME="baseCore",v.ATTRS={initialized:{readOnly:!0,value:!1},destroyed:{readOnly:!0,value:!1}},v.modifyAttrs=function(t,n){typeof t!="function"&&(n=t,t=this);var r,i,s;r=t.ATTRS||(t.ATTRS={});if(n){t._CACHED_CLASS_DATA=null;for(s in n)n.hasOwnProperty(s)&&(i=r[s]||(r[s]={}),e.mix(i,n[s],!0))}},v.prototype={_initBase:function(t){e.stamp(this),this._initAttribute(t);var n=e.Plugin&&e.Plugin.Host;this._initPlugins&&n&&n.call(this),this._lazyAddAttrs!==!1&&(this._lazyAddAttrs=!0),this.name=this.constructor.NAME,this.init.apply(this,arguments)},_initAttribute:function(){p.call(this)},init:function(e){return this._baseInit(e),this},_baseInit:function(e){this._initHierarchy(e),this._initPlugins&&this._initPlugins(e),this._set(s,!0)},destroy:function(){return this._baseDestroy(),this},_baseDestroy:function(){this._destroyPlugins&&this._destroyPlugins(),this._destroyHierarchy(),this._set(o,!0)},_getClasses:function(){return this._classes||this._initHierarchyData(),this._classes},_getAttrCfgs:function(){return this._attrs||this._initHierarchyData(),this._attrs},_filterAttrCfgs:function(e,t){var r=null,i,s,o,u,a,f,l,c=this._filteredAttrs,h=e.ATTRS;if(h)for(f in h){l=t[f];if(l&&!c.hasOwnProperty(f)){r||(r={}),i=r[f]=d({},l,this._attrCfgHash()),c[f]=!0,s=i.value,s&&typeof s=="object"&&this._cloneDefaultValue(f,i);if(t._subAttrs&&t._subAttrs.hasOwnProperty(f)){u=t._subAttrs[f];for(a in u)o=u[a],o.path&&n.setValue(i.value,o.path,o.value)}}}return r},_filterAdHocAttrs:function(e,t){var n,r=this._nonAttrs,i;if(t){n={};for(i in t)!e[i]&&!r[i]&&t.hasOwnProperty(i)&&(n[i]={value:t[i]})}return n},_initHierarchyData:function(){var e=this.constructor,t=e._CACHED_CLASS_DATA,n,r,i,s,o,u=!e._ATTR_CFG_HASH,a,f={},l=[],c=[];n=e;if(!t){while(n){l[l.length]=n,n.ATTRS&&(c[c.length]=n.ATTRS);if(u){s=n._ATTR_CFG,o=o||{};if(s)for(r=0,i=s.length;r<i;r+=1)o[s[r]]=!0}a=n._NON_ATTRS_CFG;if(a)for(r=0,i=a.length;r<i;r++)f[a[r]]=!0;n=n.superclass?n.superclass.constructor:null}u&&(e._ATTR_CFG_HASH=o),t=e._CACHED_CLASS_DATA={classes:l,nonAttrs:f,attrs:this._aggregateAttrs(c)}}this._classes=t.classes,this._attrs=t.attrs,this._nonAttrs=t.nonAttrs},_attrCfgHash:function(){return this.constructor._ATTR_CFG_HASH},_cloneDefaultValue:function(t,n){var i=n.value,s=n.cloneDefaultValue;s===l||s===!0?n.value=e.clone(i):s===c?n.value=e.merge(i):s===undefined&&(f===i.constructor||r.isArray(i))&&(n.value=e.clone(i))},_aggregateAttrs:function(e){var t,n,r,s,o,u,f=this._attrCfgHash(),l,c={};if(e)for(u=e.length-1;u>=0;--u){n=e[u];for(t in n)n.hasOwnProperty(t)&&(s=d({},n[t],f),o=null,t.indexOf(i)!==-1&&(o=t.split(i),t=o.shift()),l=c[t],o&&l&&l.value?(r=c._subAttrs,r||(r=c._subAttrs={}),r[t]||(r[t]={}),r[t][o.join(i)]={value:s.value,path:o}):o||(l?(l.valueFn&&a in s&&(l.valueFn=null),d(l,s,f)):c[t]=s))}return c},_initHierarchy:function(e){var t=this._lazyAddAttrs,n,r,i,s,o,a,f,l=this._getClasses(),c=this._getAttrCfgs(),h=l.length-1;this._filteredAttrs={};for(i=h;i>=0;i--){n=l[i],r=n.prototype,f=n._yuibuild&&n._yuibuild.exts;if(f)for(s=0,o=f.length;s<o;s++)f[s].apply(this,arguments);this.addAttrs(this._filterAttrCfgs(n,c),e,t),this._allowAdHocAttrs&&i===h&&this.addAttrs(this._filterAdHocAttrs(c,e),e,t),r.hasOwnProperty(u)&&r.initializer.apply(this,arguments);if(f)for(s=0;s<o;s++)a=f[s].prototype,a.hasOwnProperty(u)&&a.initializer.apply(this,arguments)}this._filteredAttrs=null},_destroyHierarchy:function(){var e,t,n,r,i,s,o,u,a=this._getClasses();for(n=0,r=a.length;n<r;n++){e=a[n],t=e.prototype,o=e._yuibuild&&e._yuibuild.exts;if(o)for(i=0,s=o.length;i<s;i++)u=o[i].prototype,u.hasOwnProperty(h)&&u.destructor.apply(this,arguments);t.hasOwnProperty(h)&&t.destructor.apply(this,arguments)}},toString:function(){return this.name+"["+e.stamp(this,!0)+"]"}},e.mix(v,p,!1,null,1),v.prototype.constructor=v,e.BaseCore=v},"3.10.0",{requires:["attribute-core"]});
