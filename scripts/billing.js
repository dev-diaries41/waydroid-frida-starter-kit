Java.perform(function() {
    var BillingClient = Java.use("com.android.billingclient.api.BillingClient");
    var BillingClient = Java.use("com.android.billingclient.api.BillingClient");

    // Hook the purchase validation method
    BillingClient.isPurchaseValid.implementation = function(purchase) {
        console.log("[*] Hooked isPurchaseValid: Returning TRUE");
        return true;  // Always return valid purchase
    };

    // Hook purchase update callback
    var PurchasesUpdatedListener = Java.use("com.android.billingclient.api.PurchasesUpdatedListener");
    var PurchasesUpdatedListener = Java.use("com.android.billingclient.api.PurchasesUpdatedListener");

    PurchasesUpdatedListener.onPurchasesUpdated.implementation = function(billingResult, purchases) {
        console.log("[*] Purchases Updated Hooked!");
        console.log("Billing Result: " + billingResult.toString());
        console.log("Purchases: " + purchases.toString());

        // Bypass failure by simulating a successful purchase
        var BillingResult = Java.use("com.android.billingclient.api.BillingResult");
        var BillingResult = Java.use("com.android.billingclient.api.BillingResult");
        billingResult = BillingResult.newBuilder()
            .setResponseCode(0)  // 0 = BillingResponseCode.OK
            .setDebugMessage("Bypassed with Frida!")
            .build();

        return this.onPurchasesUpdated(billingResult, purchases);
    };
});
