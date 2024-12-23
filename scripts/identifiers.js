Java.perform(function() {
    var Build = Java.use('android.os.Build');
    var SettingsSecure = Java.use('android.provider.Settings$Secure');

    // Realistic Device Values
    Build.MODEL.value = "Pixel 6";
    Build.MANUFACTURER.value = "Google";
    Build.BRAND.value = "Google";
    Build.SERIAL.value = "FAKE123456789";
    Build.FINGERPRINT.value = "google/raven/raven:13/TQ2A.230405.003/9859408:user/release-keys";
    Build.DEVICE.value = "raven";
    Build.PRODUCT.value = "raven";

    // Override Android ID
    SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        if (name === "android_id") {
            send("Bypassing Android ID check");
            return "abcdef1234567890";  // Realistic Android ID
        }
        return this.getString.call(this, cr, name);
    };

    // Override System Properties
    var SystemProperties = Java.use('android.os.SystemProperties');
    SystemProperties.get.overload('java.lang.String').implementation = function(key) {
        if (key === "ro.product.model") {
            return "Pixel 6";
        } else if (key === "ro.product.device") {
            return "raven";
        } else if (key === "ro.product.brand") {
            return "Google";
        }
        return this.get.call(this, key);
    };

    send("Device properties updated with realistic values");
});
