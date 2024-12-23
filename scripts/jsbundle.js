// script to change the js bundle file that is loaded at runtime.
const ReactNativeHost = Java.use("com.facebook.react.ReactNativeHost");
ReactNativeHost["getJSBundleFile"].implementation = function () {
    console.log(`ReactNativeHost.getJSBundleFile is called`);
    return "/data/local/tmp/BridgeReactNativeDevBundle.js";
};