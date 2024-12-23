Java.perform(function () {
    try {
        // var ReactActivity = Java.use("com.facebook.react.ReactActivity");
        // var ReactApplicationContext = Java.use("com.facebook.react.bridge.ReactApplicationContext");
        // var ReactContext = Java.use("com.facebook.react.bridge.ReactContext");
        // var Events = Java.use("com.facebook.react.uimanager.events.Event")
        // var ReactEventEmitter = Java.use("com.facebook.react.uimanager.events.ReactEventEmitter")
        // var NativeMap = Java.use("com.facebook.react.bridge.NativeMap");
        // var WritableNativeMap = Java.use("com.facebook.react.bridge.WritableNativeMap");
        // var ReadableNativeMap = Java.use("com.facebook.react.bridge.ReadableNativeMap");
        // var ReactViewGroup = Java.use("com.facebook.react.views.view.ReactViewGroup");
        // var CxxCallbackImpl = Java.use("com.facebook.react.bridge.CxxCallbackImpl");
        // var ReadableNativeArray = Java.use("com.facebook.react.bridge.ReadableNativeArray");
        // var SQLiteOpenHelper = Java.use("android.database.sqlite.SQLiteOpenHelper");
        // var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase"); 
        var Parcelable = Java.use('android.os.Parcelable');

        var classesToHook = [
            // ReactActivity,
            // ReactApplicationContext,
            // ReactContext,
            // Events,
            // ReactEventEmitter,
            // NativeMap,
            // PrecomputedText,
            // CallServerInterceptor,
            // InputMethodManager,
            // TextServicesManager
            Parcelable,
            // ReadableNativeMap,
            // ReactViewGroup,
            // CxxCallbackImpl,
            // View,
            // Button,
            // ReadableNativeArray,
            // SQLiteOpenHelper,
            // SQLiteDatabase,
            // MaterialButton
            
        ]

        // Names of obfuscated methods for further inspection
        var r8LambdaMethods = [];
        var nestMethods = [];

        classesToHook.forEach(classToHook => hookMethods(classToHook, r8LambdaMethods, nestMethods))

        // Send the collected methods
        // send({ r8LambdaMethods, nestMethods });

        console.log("[INFO] Hooking complete.");
    } catch (error) {
        console.error("[ERROR] An error occurred while hooking methods:", error);
    }
});

function hookMethods(clazz, r8LambdaMethods, nestMethods, methodsFilter=[]) {
    try {
        clazz.class.getDeclaredMethods().forEach(function (method) {
            var methodName = method.getName();
            if (methodName.includes("-$$Nest$")) {
                console.log("[NEST] Found Nest obfuscated method: " + methodName);
                nestMethods.push({ clazz, methodName });
            }

            else if (methodName.includes("$r8")) {
                console.log("[R8 LAMBDA] Found R8 obfuscated method: " + methodName);
                r8LambdaMethods.push({ clazz: clazz, methodName: methodName });
            }else{
                console.log("[HOOK] Found method: " + methodName + " in class: " + clazz);
            }
            
            var enableFilter = methodsFilter.includes(methodName) &&  methodsFilter.length > 0

            // Check if method has overloads
            if (clazz[methodName] && clazz[methodName].overloads && (enableFilter? enableFilter: true)) {
                clazz[methodName].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        try {

                            var result = overload.apply(this, arguments);
                            const methodInvokation = {class: clazz, methodName, args: arguments, returnVal:result}
                            console.log(JSON.stringify(methodInvokation, null, 2))

                            return result;
                        } catch (innerError) {
                            console.error("[ERROR] An error occurred in the method '" + methodName + "':", innerError);
                            throw innerError; // Re-throw the error to preserve the flow
                        }
                    };
                });
            } else {
                // If method is obfuscated (doesn't have overloads), check if it's an R8 lambda method or Nest method
                if((methodName.includes("r8") || methodName.includes("-$$Nest$"))){
                    console.warn("[WARNING] Method '" + methodName + "' has no overloads.");
                }else{
                    console.warn("[WARNING] Method '" + methodName + "'could not be found.");
                }
            }
        });
    } catch (error) {
        console.error("[ERROR] An error occurred while hooking methods for class: " + clazz.className, error);
    }
}