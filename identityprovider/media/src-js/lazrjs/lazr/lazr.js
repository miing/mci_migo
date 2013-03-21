/* Copyright (c) 2009, Canonical Ltd. All rights reserved. */

YUI.add('lazr.base', function(Y) {

var UI = Y.namespace('lazr.ui');

var LAZR = 'lazr';
var getCN = Y.ClassNameManager.getClassName;

/**
 * The LAZR standard 'positive' glyph as an HTML button template.  Used for
 * "Ok" buttons, confirmations, etc.  It uses an image sprite for the icon.
 *
 * The button's default text is "Ok", and its default type is 'button'.
 * http://www.w3.org/TR/html4/interact/forms.html#h-17.5
 *
 * @property lazr.ui.OK_BUTTON
 * @type String
 * @static
 */
UI.OK_BUTTON = '<button type="button" class="lazr-pos lazr-btn">Ok</button>';

/**
 * The LAZR standard 'negative' glyph as an HTML button template.  Used for
 * "Cancel" buttons, etc.  It uses an image sprite for the icon.
 *
 * The button's default text is "Cancel", and its default type is 'button'.
 * http://www.w3.org/TR/html4/interact/forms.html#h-17.5
 *
 * @property lazr.ui.CANCEL_BUTTON
 * @type String
 * @static
 */
UI.CANCEL_BUTTON = '<button type="button" class="lazr-neg lazr-btn">Cancel</button>';

/**
 * The LAZR standard 'search' glyph as an HTML button template.  Used for
 * "Search" buttons, etc.  It uses an image sprite for the icon.
 *
 * The button's default text is "Search", and its default type is 'button'.
 * http://www.w3.org/TR/html4/interact/forms.html#h-17.5
 *
 * @property lazr.ui.SEARCH_BUTTON
 * @type String
 * @static
 */
UI.SEARCH_BUTTON = '<button type="button" class="lazr-search lazr-btn">Search</button>';

/**
 * The LAZR standard 'previous' glyph as an HTML button template.  Used for
 * "previous"-type buttons.  It uses an image sprite for the icon.
 *
 * The button's default text is "Previous", and its default type is 'button'.
 * http://www.w3.org/TR/html4/interact/forms.html#h-17.5
 *
 * @property lazr.ui.PREVIOUS_BUTTON
 * @type String
 * @static
 */
UI.PREVIOUS_BUTTON = '<button type="button" class="lazr-prev lazr-btn">Previous</button>';

/**
 * The LAZR standard 'next' glyph as an HTML button template.  Used for
 * "next"-type buttons.  It uses an image sprite for the icon.
 *
 * The button's default text is "Next", and its default type is 'button'.
 * http://www.w3.org/TR/html4/interact/forms.html#h-17.5
 *
 * @property lazr.ui.NEXT_BUTTON
 * @type String
 * @static
 */
UI.NEXT_BUTTON = '<button type="button" class="lazr-next lazr-btn">Next</button>';

/**
 * Standard CSS class for even elements in a listing.
 *
 * @property lazr.ui.CSS_EVEN
 * @type String
 * @static
 */
UI.CSS_EVEN = getCN(LAZR, 'even');

/**
 * Standard CSS class for odd elements in a listing.
 *
 * @property lazr.ui.CSS_ODD
 * @type String
 * @static
 */
UI.CSS_ODD = getCN(LAZR, 'odd');

/**
 * This function forces a class to have a tabIndex attribute which
 * takes the widget's boundingBox out of the tab order.
 * It is intended to be called on subclasses of Widget.
 *
 * Use with caution.  tabindex is intended as a usability feature, for
 * keyboard accessibility, and visual feedback.  If you disable it, be sure to
 * have a really good reason, or a replacement ready.
 *
 * @method disableTabIndex
 * @param {Class} widget_class Widget that should not be in the tab order.
 */
UI.disableTabIndex = function(widget_class) {
    if (widget_class === undefined) {
        throw "disableTabIndex() must be called after ATTRS " +
              "is set on the widget.";
    }
    widget_class.ATTRS.tabIndex = {
        readOnly: true,
        value: -1
    };
};

/**
 * Standard class for the UI 'waiting for new content' indicator.
 *
 * @property lazr.ui.CSS_WAITING
 * @type String
 * @static
 */
UI.CSS_WAITING = 'lazr-waiting';

/**
 * This function sets the lazr 'waiting' CSS class on the given node.
 *
 * @method waiting
 * @param node {Node} The node to apply the CSS 'waiting' class to.
 * @chainable
 */
UI.waiting = function(node) {
    node.addClass(UI.CSS_WAITING);
};

/**
 * Clears the lazr 'waiting' CSS class from the given node.
 *
 * @method clear_waiting
 * @param node {Node} The node to remove the class from.
 * @chainable
 */
UI.clear_waiting = function(node) {
    node.removeClass(UI.CSS_WAITING);
};


}, "0.1", {"skinnable": true, "requires": ["classnamemanager"]});
