Java.perform(function () {
    try {
        var Events = Java.use("com.facebook.react.uimanager.events.Event")
        var ReactEventEmitter = Java.use("com.facebook.react.uimanager.events.ReactEventEmitter")
        var NativeModuleRegistry = Java.use('com.facebook.react.bridge.NativeModuleRegistry');
        var JavaScriptExecutor = Java.use('com.facebook.react.bridge.JavaScriptExecutor');
        var DeviceEventManagerModule = Java.use('com.facebook.react.modules.core.DeviceEventManagerModule$RCTDeviceEventEmitter');
        var JSCExecutor = Java.use('com.facebook.react.jscexecutor.JSCExecutor');
        var JSIContext = Java.use('expo.modules.kotlin.jni.JSIContext');
        var JSBundleLoader = Java.use('com.facebook.react.bridge.JSBundleLoader');
        var JSCExecutorFactory = Java.use('com.facebook.react.jscexecutor.JSCExecutorFactory');
        var JSCInstance = Java.use('com.facebook.react.runtime.JSCInstance');




        var classesToHook = [
            Events,
            ReactEventEmitter,
            JavaScriptExecutor,
            NativeModuleRegistry,
            DeviceEventManagerModule,
            JSCExecutor,
            JSIContext,
            JSBundleLoader,
            JSCExecutorFactory,
            JSCInstance
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