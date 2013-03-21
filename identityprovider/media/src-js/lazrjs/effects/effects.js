/*
    Copyright (c) 2009, Canonical Ltd.  All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

YUI.add('lazr.effects', function(Y) {

/**
 * Visual effects built on top of the YUI Animation library.
 *
 * @module lazr.effects
 * @namespace lazr.effects
 */

var namespace = Y.namespace('lazr.effects');

var OPENED = 'lazr-opened';
var CLOSED = 'lazr-closed';

/* Defaults for the slide_in and slide_out effects. */
namespace.slide_effect_defaults = {
    easing: Y.Easing.easeOut,
    duration: 0.4
};


/**
 * Produces a simple slide-out drawer effect as a Y.Anim object.
 *
 * Starts by setting the container's overflow to 'hidden', display to 'block',
 * and height to '0'.  After the animation is complete, sets the
 * <code>drawer_closed</code> attribute on the animation object to
 * <code>false</code>, and sets the container overflow to 'visible'.
 *
 * The target node obtains the 'lazr-opened' CSS class when open,
 * 'lazr-closed' when closed.
 *
 * This animation is reversible.
 *
 * @method slide_out
 * @public
 * @param node {Node|HTMLElement|Selector}  The node to apply the effect to.
 * @param user_cfg {Y.Anim config} Additional Y.Anim config parameters.
 *     These will override the default parameters of the same name.
 * @return {Y.Anim} A new animation instance.
 */
namespace.slide_out = function(node, user_cfg) {
    var cfg = Y.merge(namespace.slide_effect_defaults, user_cfg);

    if (typeof cfg.node == 'undefined') {
        cfg.node = node;
    }

    var node = Y.one(node);
    if (node === null) {
        Y.fail("A valid node, HTMLElement, or CSS3 selector must be given " +
               "for the slide_out animation.");
        return null;
    }

    var default_to_height = function(node) {
        return node.get('scrollHeight');
    };

    // We don't want to stomp on what the user may have given as the
    // from.height and to.height;
    cfg.from        = cfg.from ? cfg.from : {};
    cfg.from.height = cfg.from.height ? cfg.from.height : 0;

    cfg.to          = cfg.to ? cfg.to : {};
    cfg.to.height   = cfg.to.height ? cfg.to.height : default_to_height;

    // Set what we need to calculate the new content's scrollHeight.
    node.setStyles({
        height:   cfg.from.height,
        overflow: 'hidden',
        display:  'block'
    });

    var anim = new Y.Anim(cfg);

    // Set a custom attribute so we can clearly track the slide direction.
    // Used when reversing the slide animation.
    anim.drawer_closed = true;
    add_slide_state_events(anim);
    node.addClass(CLOSED);

    return anim;
};


/**
 * Produces a simple slide-out drawer effect as a Y.Anim object.
 *
 * After the animation is complete, sets the
 * <code>drawer_closed</code> attribute on the animation object to
 * <code>true</code>.
 *
 * The target node obtains the 'lazr-opened' CSS class when open,
 * 'lazr-closed' when closed.
 *
 * This animation is reversible.
 *
 * @method slide_in
 * @public
 * @param node {Node|HTMLElement|Selector}  The node to apply the effect to.
 * @param user_cfg {Y.Anim config} Additional Y.Anim config parameters.
 *     These will override the default parameters of the same name.
 * @return {Y.Anim} A new animation instance.
 */
namespace.slide_in = function(node, user_cfg) {
    var cfg = Y.merge(namespace.slide_effect_defaults, user_cfg);

    if (typeof cfg.node == 'undefined') {
        cfg.node = node;
    }

    var node = Y.one(node);
    if (node === null) {
        Y.fail("A valid node, HTMLElement, or CSS3 selector must be given " +
               "for the slide_in animation.");
        return null;
    }

    var default_from_height = node.get('clientHeight');

    // We don't want to stomp on what the user may have given as the
    // from.height and to.height;
    cfg.from        = cfg.from ? cfg.from : {};
    cfg.from.height = cfg.from.height ? cfg.from.height : default_from_height;

    cfg.to          = cfg.to ? cfg.to : {};
    cfg.to.height   = cfg.to.height ? cfg.to.height : 0;

    var anim = new Y.Anim(cfg);

    // Set a custom attribute so we can clearly track the slide direction.
    // Used when reversing the slide animation.
    anim.drawer_closed = false;
    add_slide_state_events(anim);
    node.addClass(OPENED);

    return anim;
};

/*
 * Events designed to handle a sliding animation's opening and closing state.
 */
function add_slide_state_events(anim) {
    var node = anim.get('node');
    anim.on('start', function() {
        if (!this.drawer_closed) {
            // We're closing the draw, so hide the overflow.
            node.setStyle('overflow', 'hidden');
        }
    });

    anim.on('end', function() {
        if (this.drawer_closed) {
            // We've finished opening the drawer, so show the overflow, just
            // to be safe.
            this.drawer_closed = false;
            node.setStyle('overflow', 'visible')
                .addClass(OPENED)
                .removeClass(CLOSED);
        } else {
            this.drawer_closed = true;
            node.addClass(CLOSED).removeClass(OPENED);
        }
    });
}


}, null, {"skinnable": true,
          "requires":["anim", "node"]});
