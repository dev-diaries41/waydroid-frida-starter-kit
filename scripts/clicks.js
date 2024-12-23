Java.perform(function () {
    // Hooking into the TouchEvent class
    var TouchEvent = Java.use("com.facebook.react.uimanager.events.TouchEvent");

    // Hook the 'dispatch' method
    TouchEvent.dispatch.overload('com.facebook.react.uimanager.events.RCTEventEmitter').implementation = function (eventEmitter) {
        console.log("[HOOK] dispatch called with eventEmitter: " + JSON.stringify(eventEmitter));

        // Optionally, you can call the original method
        return this.dispatch(eventEmitter);
    };

    // Hook the 'dispatchModern' method if present (for modern dispatch)
    if (TouchEvent.dispatchModern) {
        TouchEvent.dispatchModern.overload('com.facebook.react.uimanager.events.RCTModernEventEmitter').implementation = function (eventEmitter) {
            console.log("[HOOK] dispatchModern called with eventEmitter: " +  JSON.stringify(eventEmitter));

            // Optionally, call the original method
            return this.dispatchModern(eventEmitter);
        };
    }

});
