if (Java.available) {
    Java.perform(function () {
        // Iterate through all loaded classes
        Java.enumerateLoadedClasses({
            onMatch: function (className) {
                try {
                    var clazz = Java.use(className);
                    var function_results = []

                    // Enumerate all methods
                    clazz.class.getDeclaredMethods().forEach(function (method) {
                        var methodName = method.getName();
                        
                        // Hook each method
                        clazz[methodName].overloads.forEach(function (overload) {
                            overload.implementation = function () {
                                var args = [];
                                for (var i = 0; i < arguments.length; i++) {
                                    args.push(arguments[i]);
                                }

                                // console.log(
                                //     `[+] Class: ${className}, Method: ${methodName}, Args: ${JSON.stringify(args)}`
                                // );

                                // // Call original method
                                // var returnVal = overload.apply(this, arguments);

                                // console.log(
                                //     `[+] Return Value from ${className}.${methodName}: ${JSON.stringify(returnVal)}`
                                // );

                                var function_result = {
                                    className,
                                    methodName,
                                    args,
                                    returnVal
                                }

                                function_results.push(function_result)

                                return result;
                            };
                        });
                    });
                } catch (e) {
                    console.error(`[!] Error hooking class ${className}: ${e}`);
                }
                
                send(function_results)
            },
            onComplete: function () {
                console.log("[*] Finished enumerating classes.");
            }
        });
    });
}
