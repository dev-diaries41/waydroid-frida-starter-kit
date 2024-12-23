Java.perform(function () {
    try {
        // Hook into android.os.Bundle
        var Bundle = Java.use('android.os.Bundle');

        Bundle.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
            console.log('[Bundle] putString: ' + key + ' = ' + value);
            return this.putString(key, value);
        };

        Bundle.getString.overload('java.lang.String').implementation = function (key) {
            var result = this.getString(key);
            console.log('[Bundle] getString: ' + key + ' = ' + result);
            return result;
        };

        Bundle.putBoolean.overload('java.lang.String', 'boolean').implementation = function (key, value) {
            console.log('[Bundle] putBoolean: ' + key + ' = ' + value);
            return this.putBoolean(key, value);
        };

        Bundle.getBoolean.overload('java.lang.String').implementation = function (key) {
            var result = this.getBoolean(key);
            console.log('[Bundle] getBoolean: ' + key + ' = ' + result);
            return result;
        };

        // Hook into org.json.JSONObject
        var JSONObject = Java.use('org.json.JSONObject');

        JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function (key, value) {
            const bypassKeys = ["model", "advertising_tracking_enabled", "device_model", "rooted", "brand", "hardware_id", "local_ip", "device_fingerprint_id", "build", "cpu_type", "identity_id"]
            if(bypassKeys.includes(key)){
                console.log("[BYPASSED KEY]: ", key)
                return this.put(key, "");
            }
            if(key ==="data" && JSON.stringify(value).includes("invitedBy")){
                console.log("[BYPASSED REFERAL DATA]: ", key + value)
                const updatedReferralData = {"$og_title":"Lemonade Referral","$canonical_identifier":"JOYMV9CD","$canonical_url":"https:\/\/lemfi.com?invitedBy=JOYMV9CD","$og_description":"Earn rewards by inviting friends.","$publicly_indexable":"true","invitedBy":"JOYMV9CD","$android_package_name":"com.lemonadeFinance.android","$desktop_url":"https:\/\/lemfi.com\/invite","$ios_app_store_id":"1533066809","referralCode":"JOYHV6CE","$ios_url":"https:\/\/itunes.apple.com\/app\/id1533066809","source":"android"}
                return (this.put(key, updatedReferralData))
            }
            console.log('[JSONObject] put: ' + key + ' = ' + value);
            return this.put(key, value);
        };

        JSONObject.getString.overload('java.lang.String').implementation = function (key) {
            var result = this.getString(key);
            if(key === "refill_credits"){
                console.log("[BYPASSED refill_credits]")
                return "55"
            }
            if(key === "signup_bonus_config"){
                console.log("Original result: ", result);
                var updatedData = {"gbp":{"enabled":true,"amount":500,"currency":"GBP"},"usd":{"enabled":true,"amount":1000,"currency":"USD"},"cad":{"enabled":true,"amount":1000,"currency":"CAD"},"eur":{"enabled":false,"amount":700,"currency":"eur"}};
                console.log("Updated result: ", JSON.stringify(updatedData));
                return JSON.stringify(updatedData);
            }
            console.log('[JSONObject] getString: ' + key + ' = ' + result);
            return result;
        };

        // Hook into org.json.JSONArray
        var JSONArray = Java.use('org.json.JSONArray');

        JSONArray.put.overload('java.lang.Object').implementation = function (value) {
            const bypassValues = ["waydroid", "WayDroid x86_64 Device"]
            if(bypassValues.some(bypassValue => typeof value === 'string'? value.includes(bypassValue) :  JSON.stringify(value).includes(bypassValue))){
                console.log("[BYPASSED VALUE]: ", value)
                return this.put("");
            }
            console.log('[JSONArray] put: ' + value);
            return this.put(value);
        };

        JSONArray.getString.overload('int').implementation = function (index) {
            var result = this.getString(index);
            console.log('[JSONArray] getString: ' + index + ' = ' + result);
            return result;
        };

        // Hook into android.content.ContentValues
        var ContentValues = Java.use('android.content.ContentValues');

        ContentValues.put.overload('java.lang.String', 'java.lang.Object').implementation = function (key, value) {
            console.log('[ContentValues] put: ' + key + ' = ' + value);
            return this.put(key, value);
        };

        ContentValues.get.overload('java.lang.String').implementation = function (key) {
            var result = this.get(key);
            console.log('[ContentValues] get: ' + key + ' = ' + result);
            return result;
        };

        // Hook into android.os.PersistableBundle
        var PersistableBundle = Java.use('android.os.PersistableBundle');

        PersistableBundle.putString.overload('java.lang.String', 'java.lang.String').implementation = function (key, value) {
            console.log('[PersistableBundle] putString: ' + key + ' = ' + value);
            return this.putString(key, value);
        };

        PersistableBundle.getString.overload('java.lang.String').implementation = function (key) {
            var result = this.getString(key);
            console.log('[PersistableBundle] getString: ' + key + ' = ' + result);
            return result;
        };

        // Hook into java.util.HashMap
        // var HashMap = Java.use('java.util.HashMap');

        // HashMap.put.overload('java.lang.Object', 'java.lang.Object').implementation = function (key, value) {
        //     console.log('[HashMap] put: ' + key + ' = ' + value);
        //     return this.put(key, value);
        // };

        // HashMap.get.overload('java.lang.Object').implementation = function (key) {
        //     var result = this.get(key);
        //     console.log('[HashMap] get: ' + key + ' = ' + result);
        //     return result;
        // };

    } catch (e) {
        console.log('[Error] Could not hook class: ' + e);
    }
});
