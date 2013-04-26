YUI.add('one-password-meter', function (Y, NAME) {

"use strict";
/**
 * A password strength meter widget.
 *
 *
 * Given the id of a password field and the name of a function that will check
 * the strength of the input password this meter will display on each character
 * entered the strength value computed by the function provided.
 *
 * @module passwordmeter
 */

 // TODO: slidedown/up should be plugged in
 var slideDown = {
        height: function(node) {
            return node.get('scrollHeight') + 'px';
        },
        duration: 0.1,
        easing: 'ease-out',
        on: {
            start: function() {
                var overflow = this.getStyle('overflow');
                if (overflow !== 'hidden') { // enable scrollHeight/Width
                    this.setStyle('overflow', 'hidden');
                    this._transitionOverflow = overflow;
                }
            },
            end: function() {
                if (this._transitionOverflow) { // revert overridden value
                    this.setStyle('overflow', this._transitionOverflow);
                    delete this._transitionOverflow;
                }
            }
        }
    },
    slideUp = {
        height: 0,
        duration: 0.1,
        easing: 'ease-out',
        on: {
            start: function () {
                this.setStyle('overflow', 'hidden');
            }
        }
    },
    PasswordMeter,

    /**
     * This function will be used to determine the password's strength. It only
     * gives a 100% strength if the password has a combination of lower case, upper
     * case, numeric and symbolic characters with at least a length of 8.
     * The function can be replaed by the user of the widget by simply supplying
     * their own function in the "func" attribute.
     * The function returns two values: strength which is an int between 0 and 100
     * and text which is one of the following strings: weak, medium, strong.
     */
     default_password_strength_function = function(password) {
        var hasLower, hasUpper, hasNumber, hasSymbol,  points, sum;

        if (password && password.length > 7) {
            hasLower = /[a-z]/.test(password) ? 1 : 0,
            hasUpper = /[A-Z]/.test(password) ? 1 : 0,
            hasNumber = /\d/.test(password) ? 1 : 0,
            hasSymbol = /[\~\`\!\@\#\$\%\^\&\*\(\)\_\-\+\=\{\}\[\]\:\;\"\'\<\>\?\|\\\,\.\/]/.test(password) ? 1 : 0,

            points = hasLower + hasUpper + hasNumber + hasSymbol,
            sum = hasLower + hasUpper + hasNumber + hasSymbol;

            if(sum === 0) {
                throw new Error('Sum for >= 7 pwds cannot be 0');
            }
        } else {
            sum = 0;
        }

        return sum;
    };


    PasswordMeter = Y.Base.create('u1PasswordMeter', Y.Widget, [], {

        _indicatorNode: null,

        initializer: function () {

            this.on('strengthChange', this._strengthChange, this);

            // revert input position
            this.before('destroy', function () {
                var input = this.get('input'),
                bb = this.get('boundingBox');

                bb.insert(input, 'before');
            });

        },



    /**
     * Handler for change events from the strength attribute
     *
     * Checks the new strength value and re-renders the indicatorNode
     *
     * @method renderUI
     * @protected
     */
     _strengthChange: function (e) {

        // no change
        if(e.prevVal === e.newVal) {
            return;
        }

        var feedback = this.get('feedback')[e.newVal],
        bb = this.get('boundingBox');

        // nuke strength className on indicator
        // add new className
        this._removeStrengthClass(bb);
        bb.addClass(this.getClassName('strength', feedback.className));

        // nuke content, add new text
        this._indicatorNode.one('p').setContent(feedback.text);

    },

    _removeStrengthClass: function (n) {
        var a = n.getAttribute('class');
        n.setAttribute('class', a.replace(/\w+-\w+-strength-\w+/, ''));
        // clean whitespace
        n.setAttribute('class', n.getAttribute('class').replace(/\s{2,}/, ''));
    },

    /**
     * Update the DOM structure and edit CSS classes.
     *
     * @method renderUI
     * @protected
     */
     renderUI: function(){

        this._renderInput();

        this._renderIndicator();

    },

    _renderInput: function () {

        var input = this.get('input'),
        bb = this.get('boundingBox'),
        cb = this.get('contentBox');

        // move input to contentBox
        input.insert(bb, input);
        cb.append(input);

        return input;

    },

    _renderIndicator: function () {

        var indicatorNode = Y.Node.create('<div></div>');

        // add class name to indicator
        indicatorNode.addClass(this.getClassName('indicatorNode'));

        // insert indicator
        this.get('input').insert(indicatorNode, 'after');

        // use width attribute
        indicatorNode.setStyle('marginLeft', this.get('input').getComputedStyle('marginLeft'));
        indicatorNode.setStyle('marginRight', this.get('input').getComputedStyle('marginRight'));
        indicatorNode.setStyle('paddingLeft', this.get('input').getComputedStyle('paddingLeft'));
        indicatorNode.setStyle('paddingRight', this.get('input').getComputedStyle('paddingRight'));

        // add meter and text
        indicatorNode.setContent('<div></div><p></p>');

        // make property
        this._indicatorNode = indicatorNode;

        return indicatorNode;

    },

    /**
     * Set the event handlers for the input element.
     *
     * @method bindUI
     * @protected
     */
     bindUI: function(){

        this.get('input').on(['keyup', 'focus', 'blur'], this.syncUI, this);

    },

    /**
     * Synchronize the DOM with our current attribute state
     *
     * @method syncUI
     * @protected
     */
     syncUI: function() {

        this._updateStrength();

        this._toggleIndicatorVisibility();

    },


    /**
     * Transitions the indicator based on input length and state
     *
     * @method _toggleIndicatorVisibility
     * @protected
     */
    _toggleIndicatorVisibility: function () {

        var h = parseInt(this._indicatorNode.getComputedStyle('height'), 10);

        // show meter after three chars
        // only transition if needed
        if(this.get('input').get('value').length > 3) {
            if(h === 0) {
                this._indicatorNode.transition(slideDown);
            }
        } else {
            if(h > 0) {
                this._indicatorNode.transition(slideUp);
            }
        }

    },

    /**
     * Re-sets the strength attribute with result from
     * passing the input value to our passwordChecker function
     *
     * @method _updateStrength
     * @protected
     */
     _updateStrength: function () {
        var pwd = this.get('input').get('value');

        this.set('strength', this.get('passwordChecker')(pwd));
    }

}, {
    ATTRS: {

        /**
         * Password field we will be monitoring
         *
         * @attribute input
         * @type Node
         * @default null
         */
         input: {
            value: null,
            setter: function(v){
                return Y.one(v);
            }
        },


        /**
         * Current password strength
         *
         * @attribute strength
         * @type Number
         * @default null
         */
         strength: {
            value: null
        },

        /**
         * Javascript function that will calculate the password's strength
         * and strength description
         * Should return an object literal in the form
         * {"color": <color of the text displaying the strength>,
         *  "text": <textual description of the strength>}
         *
         * @attribute passwordChecker
         * @type function
         * @default a standard password strength function
         */
         passwordChecker: {
            value: default_password_strength_function,
            validator: function(val) {
                return Y.Lang.isFunction(val);
            }
        },

        /**
         * Array defining how the various strengths are to be
         * communicated to the user
         *
         * TODO: use strings pattern instead
         *
         * @attribute passwordChecker
         * @type function
         * @default a standard password strength function
         */
         feedback: {
            value: [
            {
                className: 'short',
                text: 'Password is too short'
            },
            {
                className: 'weak',
                text: 'Strength: weak'
            },
            {
                className: 'fair',
                text: 'Strength: fair'
            },
            {
                className: 'good',
                text: 'Strength: good'
            },
            {
                className: 'strong',
                text: 'Strength: strong'
            }

            ]
        }

    }
});

/**
 * The HTML_PARSER static constant is used by the Widget base class to
 * populate the configuration for the PasswordMeter instance from markup
 * already on the page.
 *
 * @property PasswordMeter.HTML_PARSER
 * @type Object
 * @static
 */
 PasswordMeter.HTML_PARSER = {};

 PasswordMeter.NAME = 'passwordmeter';

 Y.namespace('U1.Widgets').PasswordMeter = PasswordMeter;


}, '@VERSION@', {"requires": ["base", "widget", "event-key", "transition"]});
